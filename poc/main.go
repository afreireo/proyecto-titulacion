package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
	"github.com/emersion/go-message/mail"
)

const (
	ServidorImap    = "imap.gmail.com:993"
	UsuarioEmail    = os.Getenv("EMAIL_USER")
	PasswordEmail   = os.Getenv("EMAIL_PASS")
	ArchivoRegistro = "historial_procesados.txt"

	// Banner estructurado para la Capa de Presentación
	CabeceraAlerta = `
<div style="background-color: #ffe6e6; border: 3px solid #ff0000; padding: 15px; margin-bottom: 20px; font-family: sans-serif;">
    <h2 style="color: #cc0000; margin-top: 0;">ANÁLISIS DE SEGURIDAD: CAPA DE INTERCONEXIÓN</h2>
    <p style="font-size: 16px; color: #333;">
        El sistema ha detectado patrones sospechosos de <strong>PHISHING</strong> en este mensaje.
    </p>
    <p><strong>RECOMENDACIÓN:</strong> No interactúe con enlaces ni proporcione credenciales.</p>
</div>
<hr>
`
)

// cargarRegistros garantiza la idempotencia del sistema: no procesar un mismo ID dos veces.
func cargarRegistros() map[string]bool {
	registros := make(map[string]bool)
	archivo, err := os.Open(ArchivoRegistro)
	if err != nil {
		return registros
	}
	defer archivo.Close()
	scanner := bufio.NewScanner(archivo)
	for scanner.Scan() {
		registros[scanner.Text()] = true
	}
	return registros
}

// registrarUid persiste el estado en el disco para resiliencia ante reinicios del servicio.
func registrarUid(uid uint32) {
	f, err := os.OpenFile(ArchivoRegistro, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%d\n", uid)
}

func iniciarServicioSeguridad(historial *map[string]bool) error {
	// Establecimiento de túnel TLS seguro
	c, err := client.DialTLS(ServidorImap, nil)
	if err != nil {
		return err
	}
	defer c.Logout()

	if err := c.Login(UsuarioEmail, PasswordEmail); err != nil {
		return err
	}
	fmt.Printf("Capa de Interconexión activa en %s\n", UsuarioEmail)

	for {
		// Seleccionamos la bandeja sin marcar correos como leídos (modo escritura permitido)
		mbox, err := c.Select("INBOX", false)
		if err != nil {
			return err
		}

		if mbox.Messages > 0 {
			// Escaneamos solo el segmento final (últimos 5) para optimizar latencia
			inicio := uint32(1)
			if mbox.Messages > 5 {
				inicio = mbox.Messages - 4
			}
			rango := new(imap.SeqSet)
			rango.AddRange(inicio, mbox.Messages)

			// Peek: true evita que Gmail marque el correo original como 'Leído'
			seccion := &imap.BodySectionName{Peek: true}
			canalMensajes := make(chan *imap.Message, 5)
			done := make(chan error, 1)

			// Fetch asíncrono para mejorar el rendimiento de la capa
			go func() {
				done <- c.Fetch(rango, []imap.FetchItem{imap.FetchEnvelope, imap.FetchUid, seccion.FetchItem()}, canalMensajes)
			}()

			for msg := range canalMensajes {
				id := fmt.Sprintf("%d", msg.Uid)
				asunto := msg.Envelope.Subject
				msgId := msg.Envelope.MessageId // Identificador único global de la cadena de correo

				if strings.Contains(asunto, "[ANALIZADO]") || (*historial)[id] {
					continue
				}

				if strings.Contains(strings.ToLower(asunto), "prueba") {
					fmt.Printf("Evento detectado: %s\n", asunto)

					// Extracción de contenido Multipart
					r := msg.GetBody(seccion)
					lector, err := mail.CreateReader(r)
					if err != nil {
						continue
					}

					var htmlOriginal string
					for {
						p, err := lector.NextPart()
						if err == io.EOF { break }
						if err != nil { break }
						switch h := p.Header.(type) {
						case *mail.InlineHeader:
							tipo, _, _ := h.ContentType()
							if tipo == "text/html" {
								contenido, _ := io.ReadAll(p.Body)
								htmlOriginal = string(contenido)
							}
						}
					}

					if htmlOriginal == "" {
						htmlOriginal = "(Contenido analizado por Capa de Interconexión)"
					}

					// Lógica de Threading: In-Reply-To y References agrupan el correo en Gmail
					remitente := msg.Envelope.From[0].Address()
					
					// Construcción manual del paquete RFC822 con cabeceras de trazabilidad
					mensajeFinal := fmt.Sprintf(
						"From: %s\r\n"+
						"To: %s\r\n"+
						"Subject: [ANALIZADO] %s\r\n"+
						"In-Reply-To: %s\r\n"+
						"References: %s\r\n"+
						"MIME-Version: 1.0\r\n"+
						"Content-Type: text/html; charset=UTF-8\r\n"+
						"\r\n"+
						"%s",
						remitente, UsuarioEmail, asunto, msgId, msgId, CabeceraAlerta+htmlOriginal,
					)

					buffer := strings.NewReader(mensajeFinal)
					// Inyección del mensaje modificado al servidor
					err = c.Append("INBOX", nil, time.Now(), buffer)
					if err != nil {
						fmt.Printf("Error en inyección: %v\n", err)
					} else {
						fmt.Printf("✅ UID %s vinculado a la conversación.\n", id)
						registrarUid(msg.Uid)
						(*historial)[id] = true
					}
				}
			}
			if err := <-done; err != nil { return err }
		}
		// Polling controlado: equilibrio entre velocidad de detección y uso de red
		time.Sleep(5 * time.Second)
	}
}

func main() {
	fmt.Println("--- CAPA DE INTERCONEXIÓN DE SEGURIDAD (GO) ---")
	uids := cargarRegistros()
	for {
		// Mecanismo de recuperación ante fallos críticos de red
		if err := iniciarServicioSeguridad(&uids); err != nil {
			fmt.Printf("Reintento programado por error de red: %v\n", err)
			time.Sleep(10 * time.Second)
		}
	}
}