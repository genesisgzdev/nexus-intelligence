"""Translate recorded observations into explanations without inventing a verdict."""
from typing import Any
from rich.console import Console
from rich.table import Table

LABELS = {
    "DNSIntelligence": "Direcciones del dominio",
    "WebIntelligence": "Página web",
    "SSLForensics": "Certificado de conexión",
    "MailIntelligence": "Correo del dominio",
    "SubdomainDiscovery": "Otros sitios del dominio",
    "SecurityValidator": "Dirección consultada",
}


def describe(module: str, data: dict[str, Any]) -> str:
    if "error" in data:
        return "No se pudo completar esta consulta. Revisa el detalle y vuelve a intentarlo."
    if module == "DNSIntelligence":
        count = sum(len(data.get(key, [])) for key in ("A", "AAAA"))
        return f"Se encontraron {count} direcciones de red. Una consulta vacía también puede deberse a un problema de conexión."
    if module == "WebIntelligence":
        status = data.get("status_code")
        if status is None:
            return "No hay una respuesta web confirmada."
        return f"La página respondió con el código {status}. " + ("Revisa el acceso al sitio." if status >= 400 else "Esto confirma una respuesta, no la seguridad del sitio.")
    if module == "SSLForensics":
        return "Se leyó el certificado. Su autenticidad no está verificada por esta consulta."
    if module == "MailIntelligence":
        count = len(data.get("mx_records", []))
        policies = [data.get("spf_record"), data.get("dmarc_record")]
        if any(value in (None, "Lookup Failed", "No Policy Detected") for value in policies):
            return f"Se encontraron {count} servidores de correo. Falta confirmar alguna protección contra la suplantación."
        return f"Se encontraron {count} servidores y registros de protección del correo. Su configuración requiere revisión."
    if module == "SubdomainDiscovery":
        return f"Se encontraron {data.get('found_count', 0)} sitios en la lista de nombres consultada. No es un inventario completo."
    return "Consulta terminada. Puedes abrir los datos para revisarla."


def show_results(target: str, results: dict[str, Any], report_path: str) -> None:
    console = Console(highlight=False)
    console.print("\nNexus · Resultados", style="bold cyan")
    console.print(target, markup=False)
    table = Table(box=None, padding=(0, 2), expand=False)
    table.add_column("Consulta", style="bold")
    table.add_column("Qué encontramos", no_wrap=False)
    for module, data in results.items():
        table.add_row(LABELS.get(module, module), describe(module, data))
    console.print(table)
    console.print("\nInforme guardado en:", style="bold")
    console.print(report_path, markup=False)
    console.print("Una observación aislada no confirma una amenaza.\n")
