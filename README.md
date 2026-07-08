# whatsappTE

Laboratorio para simular una integración entre WhatsApp Business Cloud API y Check Point:

- Reputation Services
- Threat Emulation Cloud API

## Flujo

1. WhatsApp envía mensajes al webhook.
2. Flask recibe el evento.
3. Si es texto, extrae URLs.
4. Si es archivo, lo descarga desde Meta.
5. Calcula SHA256.
6. Consulta Reputation Services.
7. Si el archivo es Unknown/Unclassified, lo envía a Threat Emulation.

## Variables de entorno

META_VERIFY_TOKEN
META_ACCESS_TOKEN
META_PHONE_NUMBER_ID

CP_REP_CLIENT_KEY
CP_REP_TOKEN

CP_TE_API_KEY
CP_TE_SERVICE_ADDRESS
CP_TE_API_VERSION

LAB_MODE

## Endpoints

GET /
GET /webhook
POST /webhook
