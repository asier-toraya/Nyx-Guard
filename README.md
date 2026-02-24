# Nyx Guard

## Qué es Nyx Guard y qué hace
Nyx Guard es una extensión de Chrome que hice para tener una lectura rápida de riesgo cuando entro en una web.
La idea no es reemplazar un antivirus ni un SOC, sino dar una capa práctica de contexto: abrir una página y ver en segundos si huele raro.

La extensión analiza señales de la página, suma un score de riesgo (`0..100`) y lo traduce a algo más intuitivo:
- riesgo alto = más peligro
- fiabilidad alta = más confianza

Además de eso:
- muestra razones claras en el popup (no solo un número)
- enseña fiabilidad en el icono para no tener que abrir nada
- puede usar VirusTotal como señal externa
- lanza una alerta si la web entra en zona peligrosa

## Vista rápida de uso
En el día a día, funciona así:
1. navegas normal por una web
2. Nyx Guard escanea la página en segundo plano
3. en el icono ves fiabilidad (badge)
4. si abres popup, ves score, nivel y razones
5. si el riesgo se dispara, salta notificación

## Instalación local
### Requisitos
- Node.js 18+
- npm
- Chrome

### Pasos
1. Instalar dependencias:
```bash
npm install
```
2. Generar build:
```bash
npm run build
```
3. Cargar extensión en Chrome:
- abre `chrome://extensions`
- activa `Developer mode`
- pulsa `Load unpacked`
- selecciona la carpeta `dist`

Si cambias código:
1. `npm run build`
2. `Reload` en Nyx Guard dentro de `chrome://extensions`

## Cómo leer la puntuación
- `riesgo` se mueve entre `0` y `100`
- `fiabilidad = 100 - riesgo`

Los niveles salen de umbrales configurables en Settings:
- `low` si `score <= lowMax`
- `medium` si `score <= mediumMax`
- `high` si `score > mediumMax`

## Qué señales usa
Nyx Guard mezcla varias fuentes:
- patrones de login sospechoso (password + keywords)
- overlays invasivos y presión para activar notificaciones
- iframes ocultos
- densidad de trackers
- estructura de DOM cargada de bloques tipo ad
- punycode en dominio
- lista de confianza/bloqueo (allowlist/denylist)
- reputación de dominio con VirusTotal (opcional)

## Integración con VirusTotal
Se activa en `Settings`:
1. abrir popup de Nyx Guard
2. `Settings`
3. activar `Use VirusTotal reputation`
4. pegar API key
5. `Save`

Estado visible en popup:
- `VT: checked` -> consulta correcta con datos útiles
- `VT: no data` -> sin datos suficientes para ese dominio
- `VT: error` -> fallo de API/red/cuota/permisos

Detalles técnicos importantes:
- consulta endpoint de dominios (`/api/v3/domains/{domain}`)
- usa cache en memoria
- aplica rate limit interno para no quemar cuota free
- manda dominio, no formularios ni datos sensibles

## Alertas de peligro
Si está activo `enableDangerAlerts`, cuando el score entra cerca de `high` Nyx Guard manda notificación.

Regla actual:
- inicio de `high`: `mediumMax + 1`
- alerta temprana: desde `highStart - 5`
- cooldown por dominio/pestaña para evitar spam

## Badge del icono (sin abrir popup)
El icono muestra la fiabilidad directamente:
- número del badge = `100 - riesgo`
- color según nivel:
  - verde: `low`
  - amarillo: `medium`
  - rojo: `high`

También actualiza el tooltip con fiabilidad, riesgo y nivel.

## UI e iconos
- icono principal: estilo neutro gris/negro con escudo y `NX`
- icono de alerta: separado para notificaciones

## Arquitectura (resumen real)
`src/content/content_script.ts`
- recoge features de la página
- envía `nyxguard:features`
- responde `nyxguard:scanNow` para re-scan inmediato

`src/background/service_worker.ts`
- orquesta el flujo
- mezcla features + trackers + VT
- calcula resultado
- guarda por pestaña
- lanza alertas
- actualiza badge

`src/scoring/engine.ts`
- aplica pesos
- usa sensibilidad
- clampa score
- calcula nivel

`src/storage/settings.ts`
- defaults y persistencia
- validación de umbrales
- parseo de allow/deny list

`src/ui/popup/*`
- score, nivel, razones
- estado VT
- Trust / Block

`src/ui/options/*`
- toggles de detección
- sensibilidad
- umbrales de nivel
- API key VT
- alertas
- allow/deny list

## Pesos actuales
Fuente: `src/scoring/rules.ts`

- `punycodeDomain`: 25
- `suspiciousLogin`: 20
- `invasiveOverlay`: 15
- `popupAbuse`: 10
- `trackerLow`: 5
- `trackerMedium`: 10
- `trackerHigh`: 15
- `adLikeLow`: 5
- `adLikeHigh`: 10
- `hiddenIframes`: 12
- `virusTotalSuspicious`: 18
- `virusTotalMaliciousLow`: 35
- `virusTotalMaliciousHigh`: 55
- `virusTotalPoorReputation`: 8
- `denylist`: 30
- `allowlist`: si entra en allowlist, el score se fuerza a 0

## Scripts
- `npm run dev` -> build en watch
- `npm run build` -> build completo + copia de estáticos
- `npm run lint` -> type-check (`tsc --noEmit`)

## Estructura
```txt
src/
  background/service_worker.ts
  content/content_script.ts
  integrations/virustotal.ts
  icons/
    nyx-main-16.png
    nyx-main-32.png
    nyx-main-48.png
    nyx-main-128.png
    nyx-alert-128.png
  scoring/
    engine.ts
    rules.ts
    types.ts
  storage/settings.ts
  ui/
    popup/
    options/
  dnr/rules.json
  manifest.json
scripts/
  build-content.js
  copy-static.js
```

## Privacidad
- no se capturan valores de formularios
- `pageTextSample` viene desactivado por defecto
- con VT activo, se envía dominio (no contenido del formulario)

## Limitaciones actuales
- sigue siendo heurístico: puede haber falsos positivos/negativos
- VT depende de cuota y estado de API key
- no reemplaza análisis profundo de malware o sandbox dinámico

## Solución de problemas rápida
### El service worker aparece "inactivo"
Normal en MV3. Se despierta al recibir eventos o mensajes.

### No veo llamadas a VirusTotal
- revisa que VT esté activado y con API key guardada
- abre popup en una página `http/https` para forzar reescaneo
- mira estado `VT:` en popup

### No me salta alerta
- confirma `enableDangerAlerts` activo
- verifica que el score realmente entra en zona de alerta
- revisa notificaciones del sistema/Chrome
- recarga extensión tras cada build

## License
Copyright (c) 2026 Asier. All rights reserved.

This repository is public for viewing purposes only.
You may not use, copy, modify, or distribute this code without prior written permission.
