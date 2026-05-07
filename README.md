# Mini IDS 🛡️

Sistema de detección de intrusiones liviano para Linux. Monitorea logs del sistema en tiempo real y alerta sobre actividad sospechosa — intentos fallidos de login, brute force y accesos no autorizados.

## ¿Qué detecta?

| Patrón | Severidad | Descripción |
|--------|-----------|-------------|
| Failed SSH | MEDIUM | Intento de autenticación SSH fallido |
| Invalid user | HIGH | Login con usuario inexistente |
| Brute force | CRITICAL | IP supera el umbral de intentos en ventana de tiempo |
| Failed sudo | HIGH | Intento fallido de escalada de privilegios |
| Successful SSH | INFO | Login exitoso (para correlación) |

## Requisitos

- Python 3.8+
- Linux con `/var/log/auth.log` o `/var/log/secure`
- `sudo` para leer logs del sistema (en algunos distros)

## Instalación

```bash
git clone https://github.com/juanpablocode-sudo/mini-ids
cd mini-ids
```

Sin dependencias externas.

## Uso

### Modo real-time (tail)

```bash
sudo python mini_ids.py --tail
```

### Analizar un log existente

```bash
sudo python mini_ids.py --analyze --log /var/log/auth.log
```

### Ajustar umbral de brute force

```bash
# Alertar si una IP tiene 3 intentos fallidos en 30 segundos
sudo python mini_ids.py --tail --threshold 3 --window 30
```

### Guardar reporte en JSON

```bash
sudo python mini_ids.py --analyze --json session_report.json
```

## Output de ejemplo

```
[*] Mini IDS started — monitoring: /var/log/auth.log
[*] Brute force threshold: 5 attempts / 60s
[*] Press Ctrl+C to stop

[MEDIUM]  2026-04-20 15:30:01  Failed SSH authentication from 192.168.1.105 (user: root)
[HIGH]    2026-04-20 15:30:02  SSH login attempt with invalid user from 192.168.1.105 (user: admin)
[HIGH]    2026-04-20 15:30:03  SSH login attempt with invalid user from 192.168.1.105 (user: ubuntu)
[CRITICAL] 2026-04-20 15:30:04  🚨 BRUTE FORCE DETECTED from 192.168.1.105 (5 attempts in 60s)
[INFO]    2026-04-20 15:31:20  Successful SSH login from 10.0.0.1 (user: juanpablo)

============================================================
  MINI IDS — SESSION SUMMARY
============================================================
  Total alerts:     8
  HIGH severity:    4
  MEDIUM severity:  2
  Brute forces:     1

  IPs with brute force activity:
    • 192.168.1.105 (5 attempts)
============================================================
```

## Logs soportados

| Sistema | Log path |
|---------|----------|
| Ubuntu / Debian | `/var/log/auth.log` |
| CentOS / RHEL | `/var/log/secure` |
| Genérico | `/var/log/syslog` |

El script auto-detecta el archivo disponible. Podés especificar uno custom con `--log`.

## Próximas features

- [ ] Notificaciones por email al detectar brute force
- [ ] Exportar IPs maliciosas para bloqueo con `iptables`
- [ ] Dashboard en tiempo real con curses
- [ ] Soporte para logs de Apache/Nginx
- [ ] Integración con AbuseIPDB para reputación de IPs

## Autor

Juan Pablo Mendez — [github.com/juanpablocode-sudo](https://github.com/juanpablocode-sudo)  
Mobile Security · Python Security Tools · Linux Security

