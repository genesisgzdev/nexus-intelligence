from reporters.html_reporter import HTMLReporter
import tempfile
import os
try:
    from xhtml2pdf import pisa
except ImportError:
    pisa = None

class PDFReporter(HTMLReporter):
    def generate(self):
        if pisa is None:
            raise RuntimeError("xhtml2pdf is not installed. Please install xhtml2pdf to generate PDFs.")
            
        # First generate HTML to a temp file
        temp_html = tempfile.NamedTemporaryFile(delete=False, suffix='.html')
        temp_html.close()
        old_path = self.output_path
        self.output_path = temp_html.name
        super().generate()
        self.output_path = old_path
        
        # Then convert to PDF
        with open(temp_html.name, "r", encoding="utf-8") as html_file:
            with open(self.output_path, "wb") as pdf_file:
                pisa_status = pisa.CreatePDF(html_file.read(), dest=pdf_file)
        
        os.unlink(temp_html.name)
        if pisa_status.err:
            raise RuntimeError("PDF generation failed.")
