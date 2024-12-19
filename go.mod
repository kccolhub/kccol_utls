module github.com/refraction-networking/utls

go 1.22.0

toolchain go1.23.0

retract (
	v1.4.1 // #218
	v1.4.0 // #218 panic on saveSessionTicket
)

require (
	github.com/andybalholm/brotli v1.0.6
	github.com/cloudflare/circl v1.3.7
	github.com/klauspost/compress v1.17.4
	golang.org/x/crypto v0.30.0
	golang.org/x/net v0.32.0
	golang.org/x/sys v0.28.0
)

require (
	golang.org/x/mobile v0.0.0-20241213221354-a87c1cf6cf46 // indirect
	golang.org/x/mod v0.22.0 // indirect
	golang.org/x/sync v0.10.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	golang.org/x/tools v0.28.0 // indirect
)
