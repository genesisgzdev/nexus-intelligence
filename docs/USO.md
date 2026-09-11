# Leer una consulta sin perderse

## Qué mirar primero

Empieza por el resumen de la terminal o del informe. Cada fila responde a una pregunta distinta. «Consulta terminada» significa que se obtuvieron datos, no que el dominio haya pasado una certificación.

Un error de conexión puede deberse a una red que filtra tráfico, un servidor detenido o un tiempo de espera demasiado corto. Repite la consulta si esperabas una respuesta. No interpretes la falta de registros como prueba de que el dominio no tiene correo o no corre riesgos.

En correo, SPF y DMARC son instrucciones publicadas por el dominio para ayudar a detectar mensajes que se hacen pasar por él. Encontrarlas es el primer paso; su contenido debe revisarse.

El módulo de certificado recoge lo que presenta el servidor. El informe recuerda que esa lectura no verifica la autenticidad del certificado.

## Dónde quedan los resultados

`reports` contiene los informes y mensajes de ejecución. `nexus_forensics.db` guarda las observaciones para consultas posteriores. Los informes de consultas repetidas tienen nombres distintos.

Puedes elegir otras ubicaciones con `NEXUS_OUTPUT_DIR` y `NEXUS_DB_PATH`. El archivo `.env` también admite esas variables. El programa necesita permiso para escribir allí.

## Ajustar la consulta

| Ajuste | Qué cambia | Valor inicial |
| --- | --- | --- |
| `NEXUS_TIMEOUT` | Segundos de espera por módulo | 15 |
| `NEXUS_MAX_CONCURRENT` | Capacidad máxima configurada para trabajos paralelos | 100 |
| `--concurrency` | Dominios consultados a la vez en un archivo | 5 |
| `--verbose` | Detalle visible en la terminal | Desactivado |

Para aumentar la capacidad cambia la configuración y el número de trabajos. Nexus rechaza un valor fuera del rango configurado en lugar de reducirlo sin avisar. Aumentar trabajos también aumenta el uso de red y memoria.

## Comparar dominios

`--file dominios.txt --correlate` compara las observaciones almacenadas para esos dominios. Puede incluir observaciones anteriores de los mismos nombres. No es una comparación limitada exclusivamente a la última ejecución.

Si indicas `TDS_LOG_PATH`, Nexus puede leer también eventos de TDS para comparar texto. El archivo debe pertenecer a un entorno que puedes consultar. La comparación se realiza localmente.

## Mensajes habituales

| Mensaje o situación | Qué hacer |
| --- | --- |
| El archivo está vacío | Añade un dominio por línea |
| Dirección restringida | Usa un destino público autorizado; Nexus no consulta redes internas |
| Una consulta no se completó | Revisa su detalle y tu conexión; luego repítela |
| Respuesta recortada | El documento superó el tamaño de lectura; no interpretes el resultado como completo |
| No hay coincidencias | No hubo texto comparable por encima del umbral |

El código de salida 0 indica que los módulos terminaron sin un error registrado. El 1 indica consultas incompletas y el 2 problemas de argumentos o del archivo de entrada. Interrumpir con Ctrl+C devuelve 130.

[Volver al inicio](../README.md) · [Detalles de funcionamiento](ARCHITECTURE.md)
