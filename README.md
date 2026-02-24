# Nyx Guard

![Nyx Guard](/NyxGuardImageL.png)

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
1. Navegas normal por una web
2. Nyx Guard escanea la página en segundo plano
3. En el icono ves fiabilidad (badge)
4. Si abres popup, ves score, nivel y razones
5. Si el riesgo se dispara, salta notificación

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
- Abre `chrome://extensions`
- Activa `Developer mode`
- Pulsa `Load unpacked`
- Selecciona la carpeta `dist`

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
- Patrones de login sospechoso (password + keywords)
- Overlays invasivos y presión para activar notificaciones
- Iframes ocultos
- Densidad de trackers
- Estructura de DOM cargada de bloques tipo ad
- Punycode en dominio
- Lista de confianza/bloqueo (allowlist/denylist)
- Reputación de dominio con VirusTotal (opcional)

## Integración con VirusTotal
Se activa en `Settings`:
1. Abrir popup de Nyx Guard
2. `Settings`
3. Activar `Use VirusTotal reputation`
4. Pegar API key
5. `Save`

Estado visible en popup:
- `VT: checked` -> consulta correcta con datos útiles
- `VT: no data` -> sin datos suficientes para ese dominio
- `VT: error` -> fallo de API/red/cuota/permisos

Detalles técnicos importantes:
- Consulta endpoint de dominios (`/api/v3/domains/{domain}`)
- Usa cache en memoria
- Aplica rate limit interno para no quemar cuota free
- Manda dominio, no formularios ni datos sensibles

## Alertas de peligro
Si está activo `enableDangerAlerts`, cuando el score entra cerca de `high` Nyx Guard manda notificación.

Regla actual:
- Inicio de `high`: `mediumMax + 1`
- Alerta temprana: desde `highStart - 5`
- Cooldown por dominio/pestaña para evitar spam

## Badge del icono (sin abrir popup)
El icono muestra la fiabilidad directamente:
- Número del badge = `100 - riesgo`
- Color según nivel:
  - Verde: `low`
  - Amarillo: `medium`
  - Rojo: `high`

También actualiza el tooltip con fiabilidad, riesgo y nivel.

## Arquitectura
`src/content/content_script.ts`
- Recoge features de la página
- Envía `nyxguard:features`
- Responde `nyxguard:scanNow` para re-scan inmediato

`src/background/service_worker.ts`
- Orquesta el flujo
- Mezcla features + trackers + VT
- Calcula resultado
- Guarda por pestaña
- Lanza alertas
- Actualiza badge

`src/scoring/engine.ts`
- Aplica pesos
- Usa sensibilidad
- Clampa score
- Calcula nivel

`src/storage/settings.ts`
- Defaults y persistencia
- Validación de umbrales
- Parseo de allow/deny list

`src/ui/popup/*`
- Score, nivel, razones
- Estado VT
- Trust / Block

`src/ui/options/*`
- Toggles de detección
- Sensibilidad
- Umbrales de nivel
- API key VT
- Alertas
- Allow/deny list

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
- No se capturan valores de formularios
- `pageTextSample` viene desactivado por defecto
- Con VT activo, se envía dominio (no contenido del formulario)

## Limitaciones actuales
- Sigue siendo heurístico: puede haber falsos positivos/negativos
- VT depende de cuota y estado de API key
- No reemplaza análisis profundo de malware o sandbox dinámico

## Solución de problemas rápida
### El service worker aparece "inactivo"
Normal en MV3. Se despierta al recibir eventos o mensajes.

### No veo llamadas a VirusTotal
- Revisa que VT esté activado y con API key guardada
- Abre popup en una página `http/https` para forzar reescaneo
- Mira estado `VT:` en popup

### No me salta alerta
- Confirma `enableDangerAlerts` activo
- Verifica que el score realmente entra en zona de alerta
- Revisa notificaciones del sistema/Chrome
- Recarga extensión tras cada build

## License
This project is licensed under the MIT License.
See [LICENSE](./LICENSE) for details.
