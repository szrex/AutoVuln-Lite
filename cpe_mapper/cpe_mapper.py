# -----------------------------------------------------
# CPE Mapper (Simple Heuristic Version)
# -----------------------------------------------------

def normalize(value):
    """
    Normalize service/product strings:
    - lowercase
    - strip spaces
    - replace spaces with underscores
    """
    if not value:
        return ""
    return value.strip().lower().replace(" ", "_")


def guess_cpe(service, product):
    """
    Simple CPE guesser for AutoRecon.
    Later we will replace this with an AI model.

    Rules:
    1. If both service and product present → combine them.
    2. If only product → use product for vendor & product.
    3. If only service → use service for vendor & product.
    """

    service = normalize(service)
    product = normalize(product)

    # Nothing provided → cannot build CPE
    if not service and not product:
        return None

    # Both service + product known
    if product and service:
        return f"cpe:/a:{product}:{service}"

    # Only product known
    if product:
        return f"cpe:/a:{product}:{product}"

    # Only service known
    return f"cpe:/a:{service}:{service}"
