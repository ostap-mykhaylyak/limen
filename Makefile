APP      := limen
VERSION  := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  := -s -w -X main.version=$(VERSION)

# Installation layout (override on the command line if needed).
SBIN_DIR := /usr/sbin
CONF_DIR := /etc/$(APP)
DATA_DIR := /var/lib/$(APP)
LOG_DIR  := /var/log/$(APP)
UNIT_DIR := /etc/systemd/system

.PHONY: all static build test vet fmt clean dirs install uninstall

all: static

build:
	go build -o bin/$(APP) ./cmd/$(APP)

static:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(APP) ./cmd/$(APP)

test:
	go test ./... -race -count=1

vet:
	go vet ./...

fmt:
	gofmt -s -w .

clean:
	rm -rf bin

dirs:
	install -d -m 0750 -o root -g root $(CONF_DIR)
	install -d -m 0750 -o root -g root $(CONF_DIR)/hosts
	install -d -m 0750 -o root -g root $(CONF_DIR)/redirects
	install -d -m 0750 -o root -g root $(CONF_DIR)/streams
	install -d -m 0750 -o root -g root $(CONF_DIR)/access
	install -d -m 0750 -o root -g root $(CONF_DIR)/users
	install -d -m 0750 -o root -g root $(CONF_DIR)/certificates
	install -d -m 0750 -o root -g root $(CONF_DIR)/history
	install -d -m 0750 -o root -g root $(DATA_DIR)
	install -d -m 0700 -o root -g root $(DATA_DIR)/certs
	install -d -m 0700 -o root -g root $(DATA_DIR)/acme
	install -d -m 0750 -o root -g root $(LOG_DIR)

install: static dirs
	install -m 0755 bin/$(APP) $(SBIN_DIR)/$(APP)
	test -f $(CONF_DIR)/config.yaml || install -m 0640 internal/bootstrap/skel/etc/$(APP)/config.yaml $(CONF_DIR)/config.yaml
	install -m 0644 internal/bootstrap/$(APP).service $(UNIT_DIR)/$(APP).service
	install -m 0644 internal/bootstrap/skel/etc/logrotate.d/$(APP) /etc/logrotate.d/$(APP)
	@echo ""
	@echo "$(APP) $(VERSION) installed. Next steps:"
	@echo "  1. review $(CONF_DIR)/config.yaml (the panel must stay on loopback)"
	@echo "  2. systemctl daemon-reload"
	@echo "  3. systemctl enable --now $(APP)"
	@echo "  4. $(APP) status"

uninstall:
	-systemctl disable --now $(APP) 2>/dev/null
	rm -f $(SBIN_DIR)/$(APP) $(UNIT_DIR)/$(APP).service /etc/logrotate.d/$(APP)
	@echo "config, data and logs left in place ($(CONF_DIR), $(DATA_DIR), $(LOG_DIR));"
	@echo "remove manually or with '$(APP) purge'"
