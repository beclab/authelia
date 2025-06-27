module github.com/authelia/authelia/v4

go 1.23.0

toolchain go1.23.7

require (
	github.com/Gurpartap/logrus-stack v0.0.0-20170710170904-89c00d8a28f4
	github.com/Khan/genqlient v0.7.0
	github.com/asaskevich/govalidator v0.0.0-20210307081110-f21760c49a8d
	github.com/beclab/lldap-client v0.0.8
	github.com/deckarep/golang-set/v2 v2.1.0
	github.com/duosecurity/duo_api_golang v0.0.0-20230203160531-b221c950c2b0
	github.com/emicklei/go-restful/v3 v3.10.1
	github.com/fasthttp/router v1.4.16
	github.com/fasthttp/session/v2 v2.4.16
	github.com/fsnotify/fsnotify v1.6.0
	github.com/go-asn1-ber/asn1-ber v1.5.4
	github.com/go-crypt/crypt v0.2.6
	github.com/go-ldap/ldap/v3 v3.4.4
	github.com/go-redis/redis/v8 v8.11.5
	github.com/go-resty/resty/v2 v2.16.2
	github.com/go-rod/rod v0.112.6
	github.com/go-sql-driver/mysql v1.7.0
	github.com/go-webauthn/webauthn v0.12.2
	github.com/golang-jwt/jwt/v4 v4.5.0
	github.com/golang/mock v1.6.0
	github.com/gomodule/redigo v1.9.2
	github.com/google/uuid v1.6.0
	github.com/hashicorp/go-retryablehttp v0.7.2
	github.com/jackc/pgx/v5 v5.3.1
	github.com/jellydator/ttlcache/v3 v3.0.1
	github.com/jmoiron/sqlx v1.3.5
	github.com/knadh/koanf/parsers/yaml v0.1.0
	github.com/knadh/koanf/providers/confmap v0.1.0
	github.com/knadh/koanf/providers/env v0.1.0
	github.com/knadh/koanf/providers/posflag v0.1.0
	github.com/knadh/koanf/providers/rawbytes v0.1.0
	github.com/knadh/koanf/v2 v2.0.0
	github.com/mitchellh/mapstructure v1.5.0
	github.com/mohae/deepcopy v0.0.0-20170929034955-c48cc78d4826
	github.com/nats-io/nats.go v1.39.1
	github.com/ory/fosite v0.44.0
	github.com/ory/herodot v0.9.13
	github.com/ory/x v0.0.541
	github.com/otiai10/copy v1.9.0
	github.com/pkg/errors v0.9.1
	github.com/pquerna/otp v1.4.0
	github.com/prometheus/client_golang v1.14.0
	github.com/prometheus/common v0.37.0
	github.com/savsgio/gotils v0.0.0-20220530130905-52f3993e8d6d
	github.com/sirupsen/logrus v1.9.0
	github.com/spf13/cobra v1.6.1
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.10.0
	github.com/test-go/testify v1.1.4
	github.com/trustelem/zxcvbn v1.0.1
	github.com/valyala/bytebufferpool v1.0.0
	github.com/valyala/fasthttp v1.44.0
	github.com/wneessen/go-mail v0.3.8
	golang.org/x/net v0.33.0
	golang.org/x/sync v0.12.0
	golang.org/x/term v0.30.0
	golang.org/x/text v0.23.0
	gopkg.in/square/go-jose.v2 v2.6.0
	gopkg.in/yaml.v3 v3.0.1
	k8s.io/api v0.26.2
	k8s.io/apimachinery v0.26.2
	k8s.io/client-go v0.26.2
	k8s.io/klog/v2 v2.130.1
	sigs.k8s.io/controller-runtime v0.14.5
)

require (
	github.com/Azure/go-ntlmssp v0.0.0-20220621081337-cb9428e4ac1e // indirect
	github.com/andybalholm/brotli v1.0.4 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc // indirect
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.2 // indirect
	github.com/cristalhq/jwt/v4 v4.0.2 // indirect
	github.com/dave/jennifer v1.6.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dgraph-io/ristretto v0.1.1 // indirect
	github.com/dgrijalva/jwt-go v3.2.0+incompatible // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/dlclark/regexp2 v1.4.0 // indirect
	github.com/dustin/go-humanize v1.0.0 // indirect
	github.com/ecordell/optgen v0.0.6 // indirect
	github.com/evanphx/json-patch/v5 v5.6.0 // indirect
	github.com/facebookgo/stack v0.0.0-20160209184415-751773369052 // indirect
	github.com/fxamacker/cbor/v2 v2.7.0 // indirect
	github.com/go-crypt/x v0.1.13 // indirect
	github.com/go-logr/logr v1.4.1 // indirect
	github.com/go-openapi/jsonpointer v0.19.5 // indirect
	github.com/go-openapi/jsonreference v0.20.0 // indirect
	github.com/go-openapi/swag v0.22.3 // indirect
	github.com/go-webauthn/x v0.1.19 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang-jwt/jwt/v5 v5.2.1 // indirect
	github.com/golang/glog v1.0.0 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/gnostic v0.5.7-v3refs // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/google/go-tpm v0.9.3 // indirect
	github.com/google/gofuzz v1.1.0 // indirect
	github.com/gorilla/websocket v1.5.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/imdario/mergo v0.3.13 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20221227161230-091c0ba34f0a // indirect
	github.com/jandelgado/gcov2lcov v1.0.5 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/knadh/koanf/maps v0.1.1 // indirect
	github.com/magiconair/properties v1.8.7 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/mattn/goveralls v0.0.11 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.4 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/nats-io/nkeys v0.4.10 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	github.com/ory/go-acc v0.2.9-0.20230103102148-6b1c9a70dbbe // indirect
	github.com/ory/go-convenience v0.1.0 // indirect
	github.com/pborman/uuid v1.2.1 // indirect
	github.com/pelletier/go-toml v1.9.5 // indirect
	github.com/pelletier/go-toml/v2 v2.0.6 // indirect
	github.com/philhofer/fwd v1.1.2 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_model v0.3.0 // indirect
	github.com/prometheus/procfs v0.8.0 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/spf13/afero v1.9.3 // indirect
	github.com/spf13/cast v1.5.0 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/viper v1.14.0 // indirect
	github.com/subosito/gotenv v1.4.1 // indirect
	github.com/tinylib/msgp v1.1.8 // indirect
	github.com/vektah/gqlparser/v2 v2.5.20 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/ysmood/goob v0.4.0 // indirect
	github.com/ysmood/gson v0.7.3 // indirect
	github.com/ysmood/leakless v0.8.0 // indirect
	golang.org/x/crypto v0.36.0 // indirect
	golang.org/x/mod v0.17.0 // indirect
	golang.org/x/oauth2 v0.24.0 // indirect
	golang.org/x/sys v0.31.0 // indirect
	golang.org/x/time v0.11.0 // indirect
	golang.org/x/tools v0.21.1-0.20240508182429-e35e4ccd0d2d // indirect
	gomodules.xyz/jsonpatch/v2 v2.2.0 // indirect
	google.golang.org/genproto v0.0.0-20221025140454-527a21cfbd71 // indirect
	google.golang.org/grpc v1.50.1 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	k8s.io/apiextensions-apiserver v0.26.1 // indirect
	k8s.io/component-base v0.26.2 // indirect
	k8s.io/kube-openapi v0.0.0-20221012153701-172d655c2280 // indirect
	k8s.io/utils v0.0.0-20221128185143-99ec85e7a448 // indirect
	sigs.k8s.io/json v0.0.0-20220713155537-f223a00ba0e2 // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.2.3 // indirect
	sigs.k8s.io/yaml v1.3.0 // indirect
)
