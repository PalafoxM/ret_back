from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "assets" / "cedula-ret-template.pdf"
FRONT_ASSETS = ROOT.parent / "ret" / "src" / "assets"


def create_template():
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    width, height = landscape(A4)
    pdf = canvas.Canvas(str(OUTPUT), pagesize=(width, height))
    navy = colors.HexColor("#073764")
    cyan = colors.HexColor("#08A9C7")
    sky = colors.HexColor("#DDF3F8")
    pale = colors.HexColor("#F5FBFC")
    gray = colors.HexColor("#526B77")

    pdf.setTitle("Plantilla Cédula RET")
    pdf.setAuthor("Registro Estatal de Turismo del Estado de Guanajuato")
    pdf.setFillColor(colors.white)
    pdf.rect(0, 0, width, height, fill=1, stroke=0)
    pdf.setFillColor(navy)
    pdf.rect(0, height - 8, width, 8, fill=1, stroke=0)
    pdf.setFillColor(cyan)
    pdf.rect(0, height - 12, width, 4, fill=1, stroke=0)

    gto_logo = FRONT_ASSETS / "ggt-2006.png"
    if gto_logo.exists():
        pdf.drawImage(ImageReader(str(gto_logo)), width - 250, height - 118, width=205, height=95, preserveAspectRatio=True, mask="auto")
    pdf.setFillColor(navy)
    pdf.setFont("Helvetica-Bold", 28)
    pdf.drawString(48, height - 65, "TURISMO")
    pdf.setFont("Helvetica-Bold", 10)
    pdf.drawString(50, height - 84, "SECRETARÍA DE TURISMO E IDENTIDAD")
    pdf.setFillColor(gray)
    pdf.setFont("Helvetica", 8)
    pdf.drawString(50, height - 100, "GOBIERNO DEL ESTADO DE GUANAJUATO")

    banner_y = height - 190
    pdf.setFillColor(colors.HexColor("#CBE6F1"))
    pdf.rect(0, banner_y, width, 74, fill=1, stroke=0)
    ret_logo = FRONT_ASSETS / "logo_ret_altb.png"
    if ret_logo.exists():
        pdf.drawImage(ImageReader(str(ret_logo)), 38, banner_y + 9, width=150, height=56, preserveAspectRatio=True, mask="auto")
    pdf.setFillColor(navy)
    pdf.setFont("Helvetica", 12)
    pdf.drawRightString(width - 42, banner_y + 15, "CONSTANCIA DE INSCRIPCIÓN")

    content_top = banner_y
    footer_y = 50
    pdf.setFillColor(pale)
    pdf.rect(0, footer_y, width, content_top - footer_y, fill=1, stroke=0)
    pdf.setFillColor(sky)
    pdf.circle(110, 28, 250, fill=1, stroke=0)
    pdf.setFillColor(colors.HexColor("#B9E1ED"))
    pdf.circle(420, -90, 315, fill=1, stroke=0)
    pdf.setFillColor(colors.HexColor("#8ACDE0"))
    pdf.circle(width - 50, -155, 340, fill=1, stroke=0)

    pdf.setFillColor(navy)
    pdf.setFont("Helvetica", 16)
    pdf.drawString(48, content_top - 43, "Emitida a favor de:")
    pdf.setFont("Helvetica", 15)
    pdf.drawString(48, content_top - 178, "Como Persona Prestadora de")
    pdf.drawString(48, content_top - 198, "Servicios Turísticos:")
    pdf.setFont("Helvetica-Bold", 7.5)
    pdf.setFillColor(gray)
    pdf.drawString(255, content_top - 95, "DOMICILIO DEL ESTABLECIMIENTO")
    pdf.drawString(255, content_top - 155, "GIRO TURÍSTICO")
    pdf.drawString(48, 129, "FECHA DE INSCRIPCIÓN")
    pdf.drawString(255, 129, "VIGENCIA")
    pdf.drawString(width - 206, 181, "CÓDIGO DE VERIFICACIÓN")

    pdf.setFillColor(gray)
    pdf.setFont("Helvetica", 6.5)
    pdf.drawString(48, 83, "Esta cédula acredita la inscripción del establecimiento en el Registro Estatal de Turismo.")
    pdf.drawString(48, 72, "No genera autorización, permiso o licencia de funcionamiento.")
    pdf.setFillColor(navy)
    pdf.setFont("Helvetica-Bold", 6.5)
    pdf.drawString(430, 83, "SELLO DIGITAL")

    pdf.setFillColor(navy)
    pdf.rect(0, 0, width, footer_y, fill=1, stroke=0)
    pdf.setFillColor(cyan)
    pdf.rect(0, footer_y - 5, width * 0.52, 5, fill=1, stroke=0)
    pdf.setFillColor(colors.white)
    pdf.setFont("Helvetica-Bold", 9)
    pdf.drawCentredString(width / 2, 29, "Registro Estatal de Turismo del Estado de Guanajuato")
    pdf.setFont("Helvetica", 6.7)
    pdf.drawCentredString(width / 2, 16, "Documento digital verificable mediante código QR y cadena de aprobación")
    pdf.save()


if __name__ == "__main__":
    create_template()
    print(OUTPUT)
