#!/bin/sh
set -e

# Detect container runtime (podman or docker)
if command -v podman >/dev/null 2>&1; then
    CONTAINER_CMD="podman"
elif command -v docker >/dev/null 2>&1; then
    CONTAINER_CMD="docker"
else
    echo "[ERROR] Ni podman ni docker fueron encontrados en el sistema."
    exit 1
fi

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT_DIR"

echo "[INFO] Usando runtime de contenedores: $CONTAINER_CMD"

# 1. Compilacion local estandar
echo "[INFO] [1/4] Compilando binarios locales..."
make clean >/dev/null 2>&1 || true
make >/dev/null 2>&1

# 2. Compilar demonio estatico (Alpine + musl + libdbus estatico)
echo "[INFO] [2/4] Compilando raven-polkit-agent-static (Alpine + Musl)..."
$CONTAINER_CMD run --rm -v "$ROOT_DIR":/src -w /src alpine:latest sh -c "
set -e
apk add --no-cache git meson gcc musl-dev expat-dev samurai pkgconf >/dev/null 2>&1
git clone --depth 1 https://gitlab.freedesktop.org/dbus/dbus.git /tmp/dbus >/dev/null 2>&1
meson setup /tmp/dbus/build /tmp/dbus \
    --prefix=/usr \
    --localstatedir=/var \
    --sysconfdir=/etc \
    -Dsystem_socket=/run/dbus/system_bus_socket \
    --default-library=static \
    -Dsystemd=disabled \
    -Dtraditional_activation=false \
    -Dtools=false \
    -Dmodular_tests=disabled >/dev/null 2>&1
samu -C /tmp/dbus/build dbus/libdbus-1.a >/dev/null 2>&1
gcc -Os -s -static -fdata-sections -ffunction-sections -Wl,--gc-sections \
    -DPROMPT_DEFAULT_PATH=\\\"/usr/lib/raven-polkit/raven-polkit-prompt\\\" \
    raven-polkit-agent.c -o raven-polkit-agent-static \
    -I/tmp/dbus -I/tmp/dbus/build \
    /tmp/dbus/build/dbus/libdbus-1.a
"

# 3. Compilar prompt compatible glibc (Debian 11 / GLIBC 2.2.5 baseline)
echo "[INFO] [3/4] Compilando raven-polkit-prompt-glibc-compat (Debian 11)..."
$CONTAINER_CMD run --rm -v "$ROOT_DIR":/src -w /src debian:11-slim sh -c "
set -e
apt-get update -qq && apt-get install -y -qq libgtk-3-dev gcc pkg-config >/dev/null 2>&1
gcc -Os -s -fdata-sections -ffunction-sections -Wl,--gc-sections \
    raven-polkit-prompt.c -o raven-polkit-prompt-glibc-compat \
    \$(pkg-config --cflags --libs gtk+-3.0)
"

# 4. Compilar prompt musl (Alpine)
echo "[INFO] [4/4] Compilando raven-polkit-prompt-musl (Alpine)..."
$CONTAINER_CMD run --rm -v "$ROOT_DIR":/src -w /src alpine:latest sh -c "
set -e
apk add --no-cache gcc musl-dev gtk+3.0-dev pkgconf >/dev/null 2>&1
gcc -Os -s -fdata-sections -ffunction-sections -Wl,--gc-sections \
    raven-polkit-prompt.c -o raven-polkit-prompt-musl \
    \$(pkg-config --cflags --libs gtk+-3.0)
"

# 5. Generar paquetes .tar.gz
echo "[INFO] Empaquetando releases .tar.gz..."
mkdir -p /tmp/pkg-glibc /tmp/pkg-musl

cp raven-polkit-agent-static /tmp/pkg-glibc/raven-polkit-agent
cp raven-polkit-prompt-glibc-compat /tmp/pkg-glibc/raven-polkit-prompt
chmod +x /tmp/pkg-glibc/*
tar -czvf raven-polkit-x86_64-linux-glibc.tar.gz -C /tmp/pkg-glibc raven-polkit-agent raven-polkit-prompt >/dev/null

cp raven-polkit-agent-static /tmp/pkg-musl/raven-polkit-agent
cp raven-polkit-prompt-musl /tmp/pkg-musl/raven-polkit-prompt
chmod +x /tmp/pkg-musl/*
tar -czvf raven-polkit-x86_64-linux-musl.tar.gz -C /tmp/pkg-musl raven-polkit-agent raven-polkit-prompt >/dev/null

rm -rf /tmp/pkg-glibc /tmp/pkg-musl

echo ""
echo "[OK] Compilacion y empaquetado completados exitosamente."
echo "=== Archivos generados ==="
ls -lh raven-polkit-*
