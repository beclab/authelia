package session

import (
	"errors"
	"time"

	"github.com/fasthttp/session/v2"
	"github.com/fasthttp/session/v2/providers/memory"
	"github.com/valyala/bytebufferpool"

	"github.com/fasthttp/session/v2/providers/redis"
	redispool "github.com/gomodule/redigo/redis"
	"k8s.io/klog/v2"
)

var _ session.Provider = &memcachedRedisSessionProvider{}

type memcachedRedisSessionProvider struct {
	cache *memory.Provider
	redis *redisProvider
}

func NewMemcachedRedisSessionProvider(cfg *redis.Config) (*memcachedRedisSessionProvider, error) {
	c, err := memory.New(memory.Config{})
	if err != nil {
		klog.Error("new memory provider error, ", err)
		return nil, err
	}

	r, err := newPooledRedisProvider(cfg)
	if err != nil {
		klog.Error("new redis provider error, ", err)
		return nil, err
	}

	return &memcachedRedisSessionProvider{
		cache: c,
		redis: r,
	}, nil
}

func (m *memcachedRedisSessionProvider) Get(id []byte) ([]byte, error) {
	data, err := m.cache.Get(id)
	if err != nil {
		klog.Error("get from memory cache error, ", err)
	}

	if data != nil {
		return data, nil
	}

	return m.redis.Get(id)
}

func (m *memcachedRedisSessionProvider) Save(id, data []byte, expiration time.Duration) error {
	err := m.cache.Save(id, data, expiration)
	if err != nil {
		klog.Error("save to memory cache error, ", err)
		err = m.cache.Destroy(id)
		if err != nil {
			klog.Error("destory memory cache error, ", err)
		}
	}

	return m.redis.Save(id, data, expiration)
}

func (m *memcachedRedisSessionProvider) Destroy(id []byte) error {
	err := m.cache.Destroy(id)
	if err != nil {
		klog.Error("destory memory cache error, ", err)
	}

	return m.redis.Destroy(id)
}

func (m *memcachedRedisSessionProvider) Regenerate(id, newID []byte, expiration time.Duration) error {
	err := m.cache.Regenerate(id, newID, expiration)
	if err != nil {
		klog.Error("regenerate to memory cache error, ", err)
		err = m.cache.Destroy(id)
		if err != nil {
			klog.Error("destory memory cache error, ", err)
		}
	}

	return m.redis.Regenerate(id, newID, expiration)
}

func (m *memcachedRedisSessionProvider) Count() int {
	return m.redis.Count()
}
func (m *memcachedRedisSessionProvider) NeedGC() bool {
	return m.cache.NeedGC()
}
func (m *memcachedRedisSessionProvider) GC() error {
	return m.cache.GC()
}

const Nil = "redis: nil" // nolint:errname

type redisProvider struct {
	keyPrefix string
	pool      *redispool.Pool
}

func newPooledRedisProvider(cfg *redis.Config) (*redisProvider, error) {
	if cfg.Addr == "" {
		return nil, errConfigAddrEmpty
	}

	p := &redisProvider{
		keyPrefix: cfg.KeyPrefix,
		pool:      newRedisPool(cfg),
	}

	// check redis conn
	conn := p.pool.Get()
	defer conn.Close()
	_, err := conn.Do("PING")
	if err != nil {
		return nil, errors.New("session redis provider init error, " + err.Error())
	}

	return p, nil
}

func (p *redisProvider) getRedisSessionKey(sessionID []byte) string {
	key := bytebufferpool.Get()
	key.SetString(p.keyPrefix)
	key.WriteString(":")
	key.Write(sessionID)

	keyStr := key.String()

	bytebufferpool.Put(key)

	return keyStr
}

// Get returns the data of the given session id
func (p *redisProvider) Get(id []byte) ([]byte, error) {
	key := p.getRedisSessionKey(id)

	conn := p.pool.Get()
	defer conn.Close()

	reply, err := redispool.Bytes(conn.Do("GET", key))
	if err != nil && err != redispool.ErrNil {
		return nil, err
	}

	return reply, nil
}

// Save saves the session data and expiration from the given session id
func (p *redisProvider) Save(id, data []byte, expiration time.Duration) error {
	key := p.getRedisSessionKey(id)

	conn := p.pool.Get()
	defer conn.Close()

	_, err := conn.Do("SET", key, data, "EX", int64(expiration.Seconds()))
	if err != nil {
		return err
	}
	return err
}

// Regenerate updates the session id and expiration with the new session id
// of the the given current session id
func (p *redisProvider) Regenerate(id, newID []byte, expiration time.Duration) error {
	key := p.getRedisSessionKey(id)
	newKey := p.getRedisSessionKey(newID)

	conn := p.pool.Get()
	defer conn.Close()

	existed, err := redispool.Int(conn.Do("EXISTS", key))
	if err != nil {
		return err
	}

	if existed == 0 {
		_, err = conn.Do("RENAME", key, newKey)
		if err != nil {
			return err
		}

		_, err = conn.Do("EXPIRE", newKey, int64(expiration.Seconds()))
		if err != nil {
			return err
		}
	}

	return nil
}

// Destroy destroys the session from the given id
func (p *redisProvider) Destroy(id []byte) error {
	key := p.getRedisSessionKey(id)
	conn := p.pool.Get()
	defer conn.Close()
	_, err := conn.Do("DEL", key)
	return err
}

// Count returns the total of stored sessions
func (p *redisProvider) Count() int {

	conn := p.pool.Get()
	defer conn.Close()

	replyMap, err := redispool.Strings(conn.Do("KEYS", p.getRedisSessionKey(all)))
	if err != nil {
		return 0
	}
	return len(replyMap)
}

// NeedGC indicates if the GC needs to be run
func (p *Provider) NeedGC() bool {
	return false
}

// GC destroys the expired sessions
func (p *Provider) GC() error {
	return nil
}

func newRedisPool(config *redis.Config) *redispool.Pool {

	server := config.Addr

	return &redispool.Pool{
		MaxIdle:     config.PoolSize,
		IdleTimeout: time.Duration(config.IdleTimeout) * time.Second,
		Dial: func() (redispool.Conn, error) {
			c, err := redispool.Dial("tcp", server)
			if err != nil {
				return nil, err
			}
			if config.Password != "" {
				if _, err := c.Do("AUTH", config.Password); err != nil {
					c.Close()
					return nil, err
				}
			}
			if _, err := c.Do("SELECT", config.DB); err != nil {
				c.Close()
				return nil, err
			}
			return c, nil
		},
		TestOnBorrow: func(c redispool.Conn, t time.Time) error {
			if time.Since(t) < time.Minute {
				return nil
			}
			_, err := c.Do("PING")
			return err
		},
	}
}
