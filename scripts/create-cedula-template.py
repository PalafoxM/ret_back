from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "assets" / "cedula-ret-template.pdf"
FRONT_ASSETS = ROOT.parent / "ret" / "src" / "assets"


def create_template():
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    width, height = A4
    pdf = canvas.Canvas(str(OUTPUT), pagesize=A4)

    navy = colors.HexColor("#073764")
    cyan = colors.HexColor("#05A9C7")
    pale = colors.HexColor("#EEF8FA")
    gray = colors.HexColor("#5D7078")

    pdf.setFillColor(colors.white)
    pdf.rect(0, 0, width, height, fill=1, stroke=0)
    pdf.setFillColor(navy)
    pdf.rect(0, height - 18, width, 18, fill=1, stroke=0)
    pdf.setFillColor(cyan)
    pdf.rect(0, height - 23, width, 5, fill=1, stroke=0)

    ret_logo = FRONT_ASSETS / "logo_ret_altb.png"
    gto_logo = FRONT_ASSETS / "ggt-2006.png"
    if ret_logo.exists():
        pdf.drawImage(ImageReader(str(ret_logo)), 46, height - 105, width=92, height=62, preserveAspectRatio=True, mask="auto")
    if gto_logo.exists():
        pdf.drawImage(ImageReader(str(gto_logo)), width - 168, height - 96, width=120, height=48, preserveAspectRatio=True, mask="auto")

    pdf.setFillColor(navy)
    pdf.setFont("Helvetica-Bold", 24)
    pdf.drawCentredString(width / 2, height - 132, "CÉDULA RET")
    pdf.setFont("Helvetica", 10)
    pdf.setFillColor(gray)
    pdf.drawCentredString(width / 2, height - 150, "REGISTRO ESTATAL DE TURISMO DEL ESTADO DE GUANAJUATO")

    pdf.setStrokeColor(cyan)
    pdf.setLineWidth(1.3)
    pdf.roundRect(40, 92, width - 80, height - 270, 12, fill=0, stroke=1)
    pdf.setFillColor(pale)
    pdf.roundRect(52, height - 237, width - 104, 54, 8, fill=1, stroke=0)

    labels = [
        ("CLAVE RET", 58, height - 279),
        ("GIRO TURÍSTICO", 58, height - 337),
        ("DOMICILIO DEL ESTABLECIMIENTO", 58, height - 395),
        ("MUNICIPIO", 58, height - 463),
        ("RFC", 330, height - 463),
        ("FECHA DE REGISTRO", 58, height - 521),
        ("FECHA DE APROBACIÓN", 330, height - 521),
    ]
    pdf.setFillColor(gray)
    pdf.setFont("Helvetica-Bold", 7.5)
    for label, x, y in labels:
        pdf.drawString(x, y, label)

    pdf.setStrokeColor(colors.HexColor("#D5E5EA"))
    for y in [height - 310, height - 368, height - 426, height - 494, height - 552]:
        pdf.line(58, y, width - 58, y)

    pdf.setFillColor(navy)
    pdf.setFont("Helvetica-Bold", 8)
    pdf.drawString(58, 180, "CÓDIGO DE VERIFICACIÓN")
    pdf.drawString(212, 180, "SELLO DIGITAL")
    pdf.setFillColor(gray)
    pdf.setFont("Helvetica", 7.2)
    text = pdf.beginText(212, 163)
    text.setLeading(10)
    text.textLine("Esta cédula acredita la inscripción del establecimiento en el Registro")
    text.textLine("Estatal de Turismo. Su autenticidad puede validarse mediante el código QR")
    text.textLine("y la cadena de aprobación incorporados en este documento.")
    pdf.drawText(text)

    pdf.setFillColor(navy)
    pdf.rect(0, 0, width, 54, fill=1, stroke=0)
    pdf.setFillColor(colors.white)
    pdf.setFont("Helvetica", 7.5)
    pdf.drawCentredString(width / 2, 32, "Secretaría de Turismo e Identidad - Gobierno del Estado de Guanajuato")
    pdf.drawCentredString(width / 2, 19, "Documento digital emitido por el Registro Estatal de Turismo")
    pdf.save()


if __name__ == "__main__":
    create_template()
    print(OUTPUT)
