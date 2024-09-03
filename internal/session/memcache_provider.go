package session

import (
	"time"

	"github.com/fasthttp/session/v2"
	"github.com/fasthttp/session/v2/providers/memory"
	"github.com/fasthttp/session/v2/providers/redis"
	"k8s.io/klog/v2"
)

var _ session.Provider = &memcachedRedisSessionProvider{}

type memcachedRedisSessionProvider struct {
	cache *memory.Provider
	redis *redis.Provider
}

func NewMemcachedRedisSessionProvider(r *redis.Provider) *memcachedRedisSessionProvider {
	c, err := memory.New(memory.Config{})
	if err != nil {
		panic(err)
	}

	return &memcachedRedisSessionProvider{
		cache: c,
		redis: r,
	}
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
	return m.redis.NeedGC()
}
func (m *memcachedRedisSessionProvider) GC() error {
	return m.redis.GC()
}
