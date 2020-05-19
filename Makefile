APP=WireGuard_Surf
# GO_BUILD_FLAGS=

all:
	go build -o $(APP) .

build:
	go build --ldflags '-extldflags "-static"' -o $(APP) 

clean:
	rm -rf $(APP)
