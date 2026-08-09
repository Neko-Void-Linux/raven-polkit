# raven-polkit

A minimalist, pure-C PolicyKit authentication agent. 

`raven-polkit` separates the D-Bus daemon from the GTK graphical prompt. The background daemon consumes ~23KB and 0 graphical libraries while idling. The GTK prompt is executed on-demand and dies immediately after authentication, freeing all memory.

## Architecture

- **Cerebro (Daemon C):** `raven-polkit-agent`. Escucha a D-Bus. No enlaza con GTK, X11 ni Wayland. Detecta la sesión de login de forma estricta a través de `/proc/self/cgroup`, respetando la política interna de `polkitd` sin invocar APIs de `systemd` externas.
- **Cara (Prompt GTK):** `raven-polkit-prompt`. Una ventana GTK súper ligera que solo se lanza cuando es necesario.

## Instalación

1. Asegúrate de tener las cabeceras de GTK3 y DBus.
2. Compila el código:
   ```bash
   make
   ```
3. Instala los binarios generados en las rutas protegidas del sistema:
   ```bash
   sudo make install
   ```

## Ejecución

### Opción A: Autostart (Window Manager) - Recomendado
La forma correcta de ejecutar el agente es dejar que herede el cgroup de sesión de tu Window Manager (`session-N.scope`).

Para dejarlo fijo, agrega esto a tu configuración de `i3` o `sway` (`~/.config/i3/config`):
```text
exec --no-startup-id exec /usr/lib/raven-polkit/raven-polkit-agent
```

Si quieres probarlo en vivo sin reiniciar tu entorno, puedes inyectarlo al gestor de ventanas así (usamos un doble `exec` para matar el shell intermedio y ahorrar RAM):
```bash
i3-msg exec 'exec /usr/lib/raven-polkit/raven-polkit-agent --debug 2>>/tmp/pa.log'
```

### Depuración en Vivo (Ver los logs)
Si necesitas ver qué está haciendo el agente por detrás o por qué falla una autenticación, no intentes correrlo desde una terminal suelta (fallará por estar fuera de la sesión gráfica).

Sigue estos 3 pasos para inyectarlo en tu entorno y leer los logs en vivo:

1. Mata cualquier agente que esté corriendo en el fondo:
   ```bash
   killall raven-polkit-agent
   ```
2. Dile a i3 que inicie una instancia nueva con el modo `--debug` encendido, tirando el texto a un archivo:
   ```bash
   i3-msg exec 'exec /usr/lib/raven-polkit/raven-polkit-agent --debug 2>>/tmp/pa.log'
   ```
3. Lee el archivo de texto en vivo desde tu terminal:
   ```bash
   tail -f /tmp/pa.log
   ```
