module github.com/myguard-labs/mailstrix

go 1.25.0

toolchain go1.25.12

require (
	github.com/Teamwork/tnef v0.0.0-20200108124832-7deabccfdb32
	github.com/bodgit/sevenzip v1.6.4
	github.com/cespare/xxhash/v2 v2.3.0
	github.com/hillu/go-yara/v4 v4.3.3
	github.com/nwaples/rardecode/v2 v2.2.5
	github.com/redis/go-redis/v9 v9.20.1
	github.com/saferwall/pe v1.6.5
	github.com/yeka/zip v0.0.0-20231116150916-03d6312748a9
	www.velocidex.com/golang/oleparse v0.0.0-20251204214047-2e3e765e26a1
)

require (
	github.com/andybalholm/brotli v1.2.1 // indirect
	github.com/ayoubfaouzi/pkcs7 v0.2.3 // indirect
	github.com/bodgit/plumbing v1.3.0 // indirect
	github.com/bodgit/windows v1.0.1 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/edsrzf/mmap-go v1.1.0 // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.7 // indirect
	github.com/klauspost/compress v1.18.6 // indirect
	github.com/pierrec/lz4/v4 v4.1.26 // indirect
	github.com/spf13/afero v1.15.0 // indirect
	github.com/stangelandcl/ppmd v0.1.0 // indirect
	github.com/teamwork/test v0.0.0-20200108114543-02621bae84ad // indirect
	github.com/teamwork/utils v1.0.0 // indirect
	github.com/ulikunitz/xz v0.5.15 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	go4.org v0.0.0-20260112195520-a5071408f32f // indirect
	golang.org/x/crypto v0.52.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/text v0.37.0 // indirect
)

replace www.velocidex.com/golang/oleparse => ./third_party/oleparse

// Versions v1.0.0–v1.2.0 were published under the old module path
// github.com/eilandert/mailstrix. Under the new path they are invalid.
retract (
	v1.2.0
	v1.1.0
	v1.0.0
)
