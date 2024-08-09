// Copyright 2023 bytetrade
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package session

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/fasthttp/session/v2/providers/redis"
	redisv8 "github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
	"github.com/valyala/bytebufferpool"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/logging"
	"github.com/authelia/authelia/v4/internal/utils"
)

type Lister struct {
	keyPrefix string
	db        redisv8.Cmdable
}

var errConfigAddrEmpty = errors.New("config Addr must not be empty")

var all = []byte("*")

// var errConfigMasterNameEmpty = errors.New("config MasterName must not be empty").

func errRedisConnection(err error) error {
	return fmt.Errorf("redis connection error: %v", err)
}

func NewLister(config schema.SessionConfiguration, certPool *x509.CertPool) (*Lister, error) {
	network := TCP

	var tlsConfig *tls.Config

	if config.Redis.TLS != nil {
		tlsConfig = utils.NewTLSConfig(config.Redis.TLS, certPool)
	}

	var addr string

	if config.Redis.Port == 0 {
		network = UNIX
		addr = config.Redis.Host
	} else {
		addr = fmt.Sprintf("%s:%d", config.Redis.Host, config.Redis.Port)
	}

	return newLister(redis.Config{
		Logger:       logging.LoggerCtxPrintf(logrus.TraceLevel),
		Network:      network,
		Addr:         addr,
		Username:     config.Redis.Username,
		Password:     config.Redis.Password,
		DB:           config.Redis.DatabaseIndex, // DB is the fasthttp/session property for the Redis DB Index.
		PoolSize:     config.Redis.MaximumActiveConnections,
		MinIdleConns: config.Redis.MinimumIdleConnections,
		IdleTimeout:  300,
		TLSConfig:    tlsConfig,
		KeyPrefix:    "authelia-session",
	})
}

func newLister(cfg redis.Config) (*Lister, error) {
	if cfg.Addr == "" {
		return nil, errConfigAddrEmpty
	}

	if cfg.Logger != nil {
		redisv8.SetLogger(cfg.Logger)
	}

	db := redisv8.NewClient(&redisv8.Options{
		Network:            cfg.Network,
		Addr:               cfg.Addr,
		Username:           cfg.Username,
		Password:           cfg.Password,
		DB:                 cfg.DB,
		MaxRetries:         cfg.MaxRetries,
		MinRetryBackoff:    cfg.MinRetryBackoff,
		MaxRetryBackoff:    cfg.MaxRetryBackoff,
		DialTimeout:        cfg.DialTimeout,
		ReadTimeout:        cfg.ReadTimeout,
		WriteTimeout:       cfg.WriteTimeout,
		PoolSize:           cfg.PoolSize,
		MinIdleConns:       cfg.MinIdleConns,
		MaxConnAge:         cfg.MaxConnAge,
		PoolTimeout:        cfg.PoolTimeout,
		IdleTimeout:        cfg.IdleTimeout,
		IdleCheckFrequency: cfg.IdleCheckFrequency,
		TLSConfig:          cfg.TLSConfig,
		Limiter:            cfg.Limiter,
	})

	if err := db.Ping(context.Background()).Err(); err != nil {
		return nil, errRedisConnection(err)
	}

	l := &Lister{
		keyPrefix: cfg.KeyPrefix,
		db:        db,
	}

	return l, nil
}

func (l *Lister) List() (map[string][]byte, error) {
	reply, err := l.db.Keys(context.Background(), l.getRedisSessionKey(all)).Result()

	if err != nil {
		return nil, err
	}

	if len(reply) == 0 {
		return nil, nil
	}

	list := make(map[string][]byte)

	for _, k := range reply {

		item, err := l.db.Get(context.Background(), k).Bytes()

		if err != nil && err != redisv8.Nil {
			return nil, err
		}

		list[k] = item
	}

	return list, nil
}

func (l *Lister) getRedisSessionKey(sessionID []byte) string {
	key := bytebufferpool.Get()
	key.SetString(l.keyPrefix)
	_, _ = key.WriteString(":")
	_, _ = key.Write(sessionID)

	keyStr := key.String()

	bytebufferpool.Put(key)

	return keyStr
}

func (l *Lister) GetSessionIDFromKey(key string) string {
	prefixLen := len(l.keyPrefix) + 1 // prefix + ":".

	if len(key) > prefixLen {
		return key[prefixLen:]
	}

	return ""
}

func (l *Lister) Destroy(ctx context.Context, key string) error {
	_, err := l.db.Del(ctx, key).Result()
	return err
}
