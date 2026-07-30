from __future__ import annotations

import io
import re
import unicodedata
from collections import Counter
from dataclasses import dataclass
from itertools import combinations
from typing import BinaryIO, Iterable

import pandas as pd


CONSOLIDATED_COLUMNS = [
    "ENTORNO",
    "FECHA_EXTRACCION",
    "ID_USUARIO_ERP",
    "ID_ROL_ASIGNADO",
    "CODIGO_ROL",
    "DESCRIPCION_ROL",
    "ID_PRIVILEGIO_REFERENCIADO",
    "ID_PRIVILEGIO_ENCONTRADO",
    "CODIGO_PRIVILEGIO",
    "DESCRIPCION_PRIVILEGIO",
    "TIPO_PRIVILEGIO",
    "ESTADO_INTEGRIDAD",
    "FECHA_ASIGNACION_ROL",
    "AUDITORIA_ASIGNACION_ROL",
    "FECHA_ASIGNACION_PRIVILEGIO",
    "AUDITORIA_PRIVILEGIO",
]


@dataclass
class Inventory:
    source_name: str
    user_roles: pd.DataFrame
    role_privileges: pd.DataFrame
    role_catalog: pd.DataFrame
    privilege_catalog: pd.DataFrame
    anomalies: pd.DataFrame
    stats: dict


def clean_text(value: object) -> str:
    if pd.isna(value):
        return ""
    return re.sub(r"\s+", " ", str(value).strip())


def normalized_key(value: object) -> str:
    text = unicodedata.normalize("NFKD", clean_text(value))
    text = "".join(char for char in text if not unicodedata.combining(char))
    return re.sub(r"[^A-Z0-9]+", "_", text.upper()).strip("_")


def detect_encoding(raw: bytes) -> str:
    sample = raw[:100_000]
    for encoding in ("utf-8-sig", "cp1252", "latin-1"):
        try:
            sample.decode(encoding)
            return encoding
        except UnicodeDecodeError:
            continue
    return "latin-1"


def _read_csv(raw: bytes, **kwargs) -> pd.DataFrame:
    encoding = detect_encoding(raw)
    return pd.read_csv(io.BytesIO(raw), encoding=encoding, low_memory=False, **kwargs)


def _uppercase_columns(frame: pd.DataFrame) -> pd.DataFrame:
    result = frame.copy()
    result.columns = [normalized_key(column) for column in result.columns]
    return result


def _find_column(frame: pd.DataFrame, candidates: Iterable[str], required: bool = True) -> str | None:
    columns = {normalized_key(column): column for column in frame.columns}
    for candidate in candidates:
        key = normalized_key(candidate)
        if key in columns:
            return columns[key]
    if required:
        raise ValueError(f"No se encontró ninguna de estas columnas: {', '.join(candidates)}")
    return None


def derive_privilege_type(code: object) -> str:
    value = clean_text(code).upper()
    if not value:
        return "SIN CLASIFICAR"
    if "(IT)" in value:
        return "ITEM / OPERACION"
    if "(GS)" in value:
        return "GRUPO DE SEGURIDAD"
    return "RAIZ FUNCIONAL"


def suggest_capability(code: object, description: object) -> str:
    text = normalized_key(f"{clean_text(code)} {clean_text(description)}")
    rules = [
        (("REAPERT", "REABR"), "REABRIR"),
        (("CIERRE", "CERRAR"), "CERRAR"),
        (("ANULAR", "ANULACION"), "ANULAR"),
        (("MODIFIC", "EDITAR"), "MODIFICAR"),
        (("ALTA", "CREAR"), "CREAR"),
        (("EMITIR", "EMISION"), "EMITIR"),
        (("LIQUID",), "GESTIONAR_LIQUIDACIONES"),
        (("COMISION",), "GESTIONAR_COMISIONES"),
        (("EXPEDIENT",), "GESTIONAR_EXPEDIENTES"),
        (("CONSULTA", "CONSULTAR", "VER", "LISTADO"), "CONSULTAR"),
    ]
    for words, capability in rules:
        if any(word in text for word in words):
            return capability
    return "SIN_CLASIFICAR"


def suggest_role_family(code: object, description: object = "") -> str:
    text = normalized_key(f"{clean_text(code)} {clean_text(description)}")
    rules = [
        (("SINIESTRO",), "SINIESTROS"),
        (("POLIZA",), "POLIZAS"),
        (("MEDIADOR", "AGENTE"), "RED_MEDIACION"),
        (("ADMIN",), "ADMINISTRACION"),
        (("SERVICIOS_CENTRALES",), "SERVICIOS_CENTRALES"),
        (("INTEGRACION",), "INTEGRACIONES"),
        (("CONSULTA",), "CONSULTA"),
        (("TEST", "PRUEBA"), "PRUEBAS"),
    ]
    for words, family in rules:
        if any(word in text for word in words):
            return family
    return "POR_CLASIFICAR"


def load_consolidated(raw: bytes, source_name: str = "inventario_consolidado.csv") -> Inventory:
    encoding = detect_encoding(raw)
    reader = pd.read_csv(
        io.BytesIO(raw),
        encoding=encoding,
        chunksize=150_000,
        low_memory=False,
        dtype=str,
    )
    user_role_parts: list[pd.DataFrame] = []
    role_privilege_parts: list[pd.DataFrame] = []
    anomaly_parts: list[pd.DataFrame] = []
    type_counts: Counter[str] = Counter()
    integrity_counts: Counter[str] = Counter()
    environment_counts: Counter[str] = Counter()
    extraction_counts: Counter[str] = Counter()
    total_rows = 0
    observed_columns: list[str] | None = None

    for chunk in reader:
        chunk = _uppercase_columns(chunk)
        if observed_columns is None:
            observed_columns = list(chunk.columns)
            missing = [column for column in CONSOLIDATED_COLUMNS if column not in observed_columns]
            if missing:
                raise ValueError(
                    "El CSV consolidado no tiene el formato esperado. Faltan: " + ", ".join(missing)
                )
        chunk = chunk.fillna("")
        total_rows += len(chunk)
        for column in chunk.columns:
            chunk[column] = chunk[column].map(clean_text)

        type_counts.update(chunk["TIPO_PRIVILEGIO"].replace("", "SIN CLASIFICAR"))
        integrity_counts.update(chunk["ESTADO_INTEGRIDAD"].replace("", "SIN INFORMAR"))
        environment_counts.update(chunk["ENTORNO"].replace("", "SIN INFORMAR"))
        extraction_counts.update(chunk["FECHA_EXTRACCION"].replace("", "SIN INFORMAR"))

        user_role_parts.append(
            chunk[
                [
                    "ENTORNO",
                    "FECHA_EXTRACCION",
                    "ID_USUARIO_ERP",
                    "ID_ROL_ASIGNADO",
                    "CODIGO_ROL",
                    "DESCRIPCION_ROL",
                    "FECHA_ASIGNACION_ROL",
                    "AUDITORIA_ASIGNACION_ROL",
                ]
            ].drop_duplicates()
        )
        role_privilege_parts.append(
            chunk[
                [
                    "ENTORNO",
                    "FECHA_EXTRACCION",
                    "ID_ROL_ASIGNADO",
                    "CODIGO_ROL",
                    "DESCRIPCION_ROL",
                    "ID_PRIVILEGIO_REFERENCIADO",
                    "ID_PRIVILEGIO_ENCONTRADO",
                    "CODIGO_PRIVILEGIO",
                    "DESCRIPCION_PRIVILEGIO",
                    "TIPO_PRIVILEGIO",
                    "ESTADO_INTEGRIDAD",
                    "FECHA_ASIGNACION_PRIVILEGIO",
                    "AUDITORIA_PRIVILEGIO",
                ]
            ].drop_duplicates()
        )
        bad = chunk[chunk["ESTADO_INTEGRIDAD"].str.upper().ne("OK")]
        if not bad.empty:
            anomaly_parts.append(
                bad[
                    [
                        "ENTORNO",
                        "FECHA_EXTRACCION",
                        "ID_USUARIO_ERP",
                        "ID_ROL_ASIGNADO",
                        "CODIGO_ROL",
                        "ID_PRIVILEGIO_REFERENCIADO",
                        "ID_PRIVILEGIO_ENCONTRADO",
                        "CODIGO_PRIVILEGIO",
                        "ESTADO_INTEGRIDAD",
                    ]
                ].drop_duplicates()
            )

    if observed_columns is None:
        raise ValueError("El archivo está vacío.")

    user_roles = pd.concat(user_role_parts, ignore_index=True).drop_duplicates()
    role_privileges = pd.concat(role_privilege_parts, ignore_index=True).drop_duplicates()
    anomalies = (
        pd.concat(anomaly_parts, ignore_index=True).drop_duplicates()
        if anomaly_parts
        else pd.DataFrame(
            columns=[
                "ENTORNO",
                "FECHA_EXTRACCION",
                "ID_USUARIO_ERP",
                "ID_ROL_ASIGNADO",
                "CODIGO_ROL",
                "ID_PRIVILEGIO_REFERENCIADO",
                "ID_PRIVILEGIO_ENCONTRADO",
                "CODIGO_PRIVILEGIO",
                "ESTADO_INTEGRIDAD",
            ]
        )
    )
    role_catalog = (
        pd.concat(
            [
                user_roles[["ID_ROL_ASIGNADO", "CODIGO_ROL", "DESCRIPCION_ROL"]],
                role_privileges[["ID_ROL_ASIGNADO", "CODIGO_ROL", "DESCRIPCION_ROL"]],
            ],
            ignore_index=True,
        )
        .drop_duplicates()
        .reset_index(drop=True)
    )
    privilege_catalog = (
        role_privileges[
            [
                "ID_PRIVILEGIO_REFERENCIADO",
                "ID_PRIVILEGIO_ENCONTRADO",
                "CODIGO_PRIVILEGIO",
                "DESCRIPCION_PRIVILEGIO",
                "TIPO_PRIVILEGIO",
            ]
        ]
        .loc[
            role_privileges["ID_PRIVILEGIO_REFERENCIADO"].map(clean_text).ne("")
        ]
        .drop_duplicates()
        .reset_index(drop=True)
    )
    stats = {
        "total_rows": total_rows,
        "encoding": encoding,
        "type_counts": dict(type_counts),
        "integrity_counts": dict(integrity_counts),
        "environment_counts": dict(environment_counts),
        "extraction_counts": dict(extraction_counts),
        "source_mode": "consolidated",
    }
    return Inventory(
        source_name=source_name,
        user_roles=user_roles,
        role_privileges=role_privileges,
        role_catalog=role_catalog,
        privilege_catalog=privilege_catalog,
        anomalies=anomalies,
        stats=stats,
    )


def load_legacy(
    user_roles_raw: bytes,
    role_functions_raw: bytes,
    roles_raw: bytes,
    functions_raw: bytes | None = None,
) -> Inventory:
    ru = _uppercase_columns(_read_csv(user_roles_raw, dtype=str).fillna(""))
    rf = _uppercase_columns(_read_csv(role_functions_raw, dtype=str).fillna(""))
    roles = _uppercase_columns(_read_csv(roles_raw, dtype=str).fillna(""))
    functions = (
        _uppercase_columns(_read_csv(functions_raw, dtype=str).fillna(""))
        if functions_raw is not None
        else pd.DataFrame()
    )

    ru_user = _find_column(ru, ["ID_DUSUARIOS_FK", "ID_USUARIO_ERP", "ID_USUARIO"])
    ru_role = _find_column(ru, ["ID_DROLES_FK", "ID_ROL_ASIGNADO", "ID_ROL"])
    rf_role = _find_column(rf, ["ID_DROLES_FK", "ID_ROL_ASIGNADO", "ID_ROL"])
    rf_function = _find_column(rf, ["ID_DFUNCION_FK", "ID_PRIVILEGIO_REFERENCIADO", "ID_DFUNCION"])
    role_id = _find_column(roles, ["ID_DROLES", "ID_ROL_ASIGNADO", "ID_ROL"])
    role_code = _find_column(roles, ["CODIGROL", "CODIGO_ROL", "ROL"])
    role_description = _find_column(
        roles, ["DESCRIPCION", "DESCRIPCION_ROL", "NOMBRE"], required=False
    )

    role_catalog = pd.DataFrame(
        {
            "ID_ROL_ASIGNADO": roles[role_id].map(clean_text),
            "CODIGO_ROL": roles[role_code].map(clean_text),
            "DESCRIPCION_ROL": (
                roles[role_description].map(clean_text) if role_description else ""
            ),
        }
    ).drop_duplicates()
    user_roles = pd.DataFrame(
        {
            "ID_USUARIO_ERP": ru[ru_user].map(clean_text),
            "ID_ROL_ASIGNADO": ru[ru_role].map(clean_text),
        }
    )
    user_roles = user_roles.merge(role_catalog, how="left", on="ID_ROL_ASIGNADO")
    user_roles["ENTORNO"] = "NO INFORMADO"
    user_roles["FECHA_EXTRACCION"] = ""
    user_roles["FECHA_ASIGNACION_ROL"] = ""
    user_roles["AUDITORIA_ASIGNACION_ROL"] = ""

    role_privileges = pd.DataFrame(
        {
            "ID_ROL_ASIGNADO": rf[rf_role].map(clean_text),
            "ID_PRIVILEGIO_REFERENCIADO": rf[rf_function].map(clean_text),
        }
    ).merge(role_catalog, how="left", on="ID_ROL_ASIGNADO")
    role_privileges["ID_PRIVILEGIO_ENCONTRADO"] = ""
    role_privileges["CODIGO_PRIVILEGIO"] = ""
    role_privileges["DESCRIPCION_PRIVILEGIO"] = ""
    role_privileges["TIPO_PRIVILEGIO"] = "SIN CLASIFICAR"
    role_privileges["ESTADO_INTEGRIDAD"] = "SIN CATALOGO DFUNCION"

    if not functions.empty:
        function_id = _find_column(
            functions, ["ID_DFUNCION", "ID_PRIVILEGIO_ENCONTRADO", "ID_PRIVILEGIO"]
        )
        function_code = _find_column(
            functions, ["FUNCICOD", "CODIGO_PRIVILEGIO", "CODIGO"], required=False
        )
        function_description = _find_column(
            functions, ["DESCRIPCION", "DESCRIPCION_PRIVILEGIO"], required=False
        )
        catalog = pd.DataFrame(
            {
                "ID_PRIVILEGIO_ENCONTRADO": functions[function_id].map(clean_text),
                "CODIGO_PRIVILEGIO": (
                    functions[function_code].map(clean_text) if function_code else ""
                ),
                "DESCRIPCION_PRIVILEGIO": (
                    functions[function_description].map(clean_text)
                    if function_description
                    else ""
                ),
            }
        ).drop_duplicates("ID_PRIVILEGIO_ENCONTRADO")
        role_privileges = role_privileges.drop(
            columns=[
                "ID_PRIVILEGIO_ENCONTRADO",
                "CODIGO_PRIVILEGIO",
                "DESCRIPCION_PRIVILEGIO",
                "TIPO_PRIVILEGIO",
                "ESTADO_INTEGRIDAD",
            ]
        ).merge(
            catalog,
            how="left",
            left_on="ID_PRIVILEGIO_REFERENCIADO",
            right_on="ID_PRIVILEGIO_ENCONTRADO",
        )
        role_privileges["TIPO_PRIVILEGIO"] = role_privileges["CODIGO_PRIVILEGIO"].map(
            derive_privilege_type
        )
        role_privileges["ESTADO_INTEGRIDAD"] = role_privileges[
            "ID_PRIVILEGIO_ENCONTRADO"
        ].apply(lambda value: "OK" if clean_text(value) else "FUNCION NO ENCONTRADA")

    role_privileges["ENTORNO"] = "NO INFORMADO"
    role_privileges["FECHA_EXTRACCION"] = ""
    role_privileges["FECHA_ASIGNACION_PRIVILEGIO"] = ""
    role_privileges["AUDITORIA_PRIVILEGIO"] = ""
    anomalies = role_privileges[
        role_privileges["ESTADO_INTEGRIDAD"].str.upper().ne("OK")
    ].copy()
    privilege_catalog = role_privileges[
        [
            "ID_PRIVILEGIO_REFERENCIADO",
            "ID_PRIVILEGIO_ENCONTRADO",
            "CODIGO_PRIVILEGIO",
            "DESCRIPCION_PRIVILEGIO",
            "TIPO_PRIVILEGIO",
        ]
    ].drop_duplicates()
    stats = {
        "total_rows": len(role_privileges),
        "encoding": "detección automática",
        "type_counts": role_privileges["TIPO_PRIVILEGIO"].value_counts().to_dict(),
        "integrity_counts": role_privileges["ESTADO_INTEGRIDAD"].value_counts().to_dict(),
        "environment_counts": {"NO INFORMADO": len(role_privileges)},
        "extraction_counts": {},
        "source_mode": "legacy",
    }
    return Inventory(
        source_name="Tres CSV originales",
        user_roles=user_roles.drop_duplicates(),
        role_privileges=role_privileges.drop_duplicates(),
        role_catalog=role_catalog.drop_duplicates(),
        privilege_catalog=privilege_catalog.drop_duplicates(),
        anomalies=anomalies.drop_duplicates(),
        stats=stats,
    )


def filter_snapshot(inventory: Inventory, environment: str, extraction_date: str) -> Inventory:
    def filtered(frame: pd.DataFrame) -> pd.DataFrame:
        result = frame
        if "ENTORNO" in result.columns and environment:
            result = result[result["ENTORNO"] == environment]
        if "FECHA_EXTRACCION" in result.columns and extraction_date:
            result = result[result["FECHA_EXTRACCION"] == extraction_date]
        return result.copy()

    user_roles = filtered(inventory.user_roles)
    role_privileges = filtered(inventory.role_privileges)
    anomalies = filtered(inventory.anomalies)
    role_ids = set(user_roles["ID_ROL_ASIGNADO"]) | set(role_privileges["ID_ROL_ASIGNADO"])
    role_catalog = inventory.role_catalog[
        inventory.role_catalog["ID_ROL_ASIGNADO"].isin(role_ids)
    ].copy()
    privilege_ids = set(role_privileges["ID_PRIVILEGIO_REFERENCIADO"])
    privilege_catalog = inventory.privilege_catalog[
        inventory.privilege_catalog["ID_PRIVILEGIO_REFERENCIADO"].isin(privilege_ids)
    ].copy()
    return Inventory(
        source_name=inventory.source_name,
        user_roles=user_roles,
        role_privileges=role_privileges,
        role_catalog=role_catalog,
        privilege_catalog=privilege_catalog,
        anomalies=anomalies,
        stats=inventory.stats,
    )


def privilege_sets(inventory: Inventory, leaf_only: bool = True) -> dict[str, set[str]]:
    frame = inventory.role_privileges.copy()
    if leaf_only and (frame["TIPO_PRIVILEGIO"] == "ITEM / OPERACION").any():
        frame = frame[frame["TIPO_PRIVILEGIO"] == "ITEM / OPERACION"]
    frame = frame[frame["ID_PRIVILEGIO_REFERENCIADO"].map(clean_text).ne("")]
    return (
        frame.groupby("ID_ROL_ASIGNADO")["ID_PRIVILEGIO_REFERENCIADO"]
        .apply(lambda values: set(values))
        .to_dict()
    )


def role_summary(inventory: Inventory) -> pd.DataFrame:
    roles = inventory.role_catalog.drop_duplicates("ID_ROL_ASIGNADO").copy()
    valid_privileges = inventory.role_privileges[
        inventory.role_privileges["ID_PRIVILEGIO_REFERENCIADO"].map(clean_text).ne("")
    ]
    user_counts = (
        inventory.user_roles.groupby("ID_ROL_ASIGNADO")["ID_USUARIO_ERP"]
        .nunique()
        .rename("USUARIOS")
    )
    all_counts = (
        valid_privileges.groupby("ID_ROL_ASIGNADO")[
            "ID_PRIVILEGIO_REFERENCIADO"
        ]
        .nunique()
        .rename("PRIVILEGIOS")
    )
    item_counts = (
        valid_privileges[valid_privileges["TIPO_PRIVILEGIO"] == "ITEM / OPERACION"]
        .groupby("ID_ROL_ASIGNADO")["ID_PRIVILEGIO_REFERENCIADO"]
        .nunique()
        .rename("ITEMS_OPERACIONES")
    )
    warning_counts = (
        inventory.role_privileges[
            inventory.role_privileges["ESTADO_INTEGRIDAD"].str.upper().ne("OK")
        ]
        .groupby("ID_ROL_ASIGNADO")
        .size()
        .rename("AVISOS_INTEGRIDAD")
    )
    result = roles.merge(user_counts, on="ID_ROL_ASIGNADO", how="left")
    result = result.merge(all_counts, on="ID_ROL_ASIGNADO", how="left")
    result = result.merge(item_counts, on="ID_ROL_ASIGNADO", how="left")
    result = result.merge(warning_counts, on="ID_ROL_ASIGNADO", how="left")
    for column in ("USUARIOS", "PRIVILEGIOS", "ITEMS_OPERACIONES", "AVISOS_INTEGRIDAD"):
        result[column] = result[column].fillna(0).astype(int)
    result["FAMILIA_SUGERIDA"] = result.apply(
        lambda row: suggest_role_family(row["CODIGO_ROL"], row["DESCRIPCION_ROL"]), axis=1
    )
    suspicious = r"TEST|PRUEBA|DESARROLLO|DEV|OLD|OBSOLET|TEMP"
    result["NOMBRE_A_REVISAR"] = result["CODIGO_ROL"].str.upper().str.contains(
        suspicious, regex=True, na=False
    )
    return result.sort_values(["USUARIOS", "CODIGO_ROL"], ascending=[False, True])


def _role_lookup(inventory: Inventory) -> dict[str, str]:
    return (
        inventory.role_catalog.drop_duplicates("ID_ROL_ASIGNADO")
        .set_index("ID_ROL_ASIGNADO")["CODIGO_ROL"]
        .to_dict()
    )


def compare_roles(
    inventory: Inventory, threshold: float = 0.85, leaf_only: bool = True
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    sets = privilege_sets(inventory, leaf_only=leaf_only)
    names = _role_lookup(inventory)
    users = (
        inventory.user_roles.groupby("ID_ROL_ASIGNADO")["ID_USUARIO_ERP"].nunique().to_dict()
    )
    identical_rows: list[dict] = []
    similar_rows: list[dict] = []
    subset_rows: list[dict] = []
    role_ids = sorted(sets, key=str)
    for role_a, role_b in combinations(role_ids, 2):
        set_a, set_b = sets[role_a], sets[role_b]
        if not set_a or not set_b:
            continue
        common = len(set_a & set_b)
        union = len(set_a | set_b)
        similarity = common / union if union else 1.0
        base = {
            "ROL_A": names.get(role_a, role_a),
            "ID_ROL_A": role_a,
            "USUARIOS_A": users.get(role_a, 0),
            "ROL_B": names.get(role_b, role_b),
            "ID_ROL_B": role_b,
            "USUARIOS_B": users.get(role_b, 0),
            "SIMILITUD_JACCARD": round(similarity, 4),
            "PRIVILEGIOS_COMUNES": common,
            "SOLO_A": len(set_a - set_b),
            "SOLO_B": len(set_b - set_a),
        }
        if set_a == set_b:
            identical_rows.append(base)
        elif similarity >= threshold:
            similar_rows.append(base)
        if set_a < set_b:
            subset_rows.append(
                {
                    "ROL_CONTENIDO": names.get(role_a, role_a),
                    "ID_ROL_CONTENIDO": role_a,
                    "ROL_CONTENEDOR": names.get(role_b, role_b),
                    "ID_ROL_CONTENEDOR": role_b,
                    "PRIVILEGIOS_CONTENIDO": len(set_a),
                    "PRIVILEGIOS_EXTRA_CONTENEDOR": len(set_b - set_a),
                    "SIMILITUD_JACCARD": round(similarity, 4),
                }
            )
        elif set_b < set_a:
            subset_rows.append(
                {
                    "ROL_CONTENIDO": names.get(role_b, role_b),
                    "ID_ROL_CONTENIDO": role_b,
                    "ROL_CONTENEDOR": names.get(role_a, role_a),
                    "ID_ROL_CONTENEDOR": role_a,
                    "PRIVILEGIOS_CONTENIDO": len(set_b),
                    "PRIVILEGIOS_EXTRA_CONTENEDOR": len(set_a - set_b),
                    "SIMILITUD_JACCARD": round(similarity, 4),
                }
            )
    identical = pd.DataFrame(identical_rows)
    similar = pd.DataFrame(similar_rows)
    subsets = pd.DataFrame(subset_rows)
    if not identical.empty:
        identical = identical.sort_values(
            ["SIMILITUD_JACCARD", "ROL_A", "ROL_B"], ascending=[False, True, True]
        )
    if not similar.empty:
        similar = similar.sort_values(
            ["SIMILITUD_JACCARD", "PRIVILEGIOS_COMUNES"], ascending=False
        )
    if not subsets.empty:
        subsets = subsets.sort_values(
            ["SIMILITUD_JACCARD", "PRIVILEGIOS_EXTRA_CONTENEDOR"], ascending=[False, True]
        )
    return identical, similar, subsets


def duplicate_privilege_definitions(inventory: Inventory) -> pd.DataFrame:
    catalog = inventory.privilege_catalog.copy()
    catalog = catalog[catalog["ID_PRIVILEGIO_REFERENCIADO"].map(clean_text).ne("")]
    catalog["CLAVE_DEFINICION"] = catalog.apply(
        lambda row: normalized_key(
            f"{row['CODIGO_PRIVILEGIO']}|{row['DESCRIPCION_PRIVILEGIO']}"
        ),
        axis=1,
    )
    grouped = (
        catalog.groupby("CLAVE_DEFINICION")
        .agg(
            IDS=("ID_PRIVILEGIO_REFERENCIADO", lambda values: " | ".join(sorted(set(values)))),
            NUM_IDS=("ID_PRIVILEGIO_REFERENCIADO", "nunique"),
            CODIGO=("CODIGO_PRIVILEGIO", "first"),
            DESCRIPCION=("DESCRIPCION_PRIVILEGIO", "first"),
        )
        .reset_index(drop=True)
    )
    return grouped[grouped["NUM_IDS"] > 1].sort_values("NUM_IDS", ascending=False)


def user_redundancy(
    inventory: Inventory, leaf_only: bool = True
) -> tuple[pd.DataFrame, pd.DataFrame]:
    sets = privilege_sets(inventory, leaf_only=leaf_only)
    names = _role_lookup(inventory)
    global_users = (
        inventory.user_roles.groupby("ID_ROL_ASIGNADO")["ID_USUARIO_ERP"].nunique().to_dict()
    )
    covered_rows: list[dict] = []
    repeated_rows: list[dict] = []
    assignments = (
        inventory.user_roles.groupby("ID_USUARIO_ERP")["ID_ROL_ASIGNADO"]
        .apply(lambda values: sorted(set(values), key=str))
        .to_dict()
    )
    for user, role_ids in assignments.items():
        role_ids = [role_id for role_id in role_ids if role_id in sets and sets[role_id]]
        privilege_to_roles: dict[str, list[str]] = {}
        for role_id in role_ids:
            for privilege in sets[role_id]:
                privilege_to_roles.setdefault(privilege, []).append(role_id)
        for privilege, granting_roles in privilege_to_roles.items():
            if len(granting_roles) > 1:
                repeated_rows.append(
                    {
                        "ID_USUARIO_ERP": user,
                        "ID_PRIVILEGIO": privilege,
                        "NUM_ROLES_QUE_LO_CONCEDEN": len(granting_roles),
                        "ROLES": " | ".join(names.get(role_id, role_id) for role_id in granting_roles),
                        "CONCESIONES_EXTRA": len(granting_roles) - 1,
                    }
                )
        candidates: list[tuple[str, str, int, bool]] = []
        for role_a, role_b in combinations(role_ids, 2):
            set_a, set_b = sets[role_a], sets[role_b]
            if set_a == set_b:
                rank_a = (-global_users.get(role_a, 0), str(role_a))
                rank_b = (-global_users.get(role_b, 0), str(role_b))
                redundant, covering = (role_b, role_a) if rank_a <= rank_b else (role_a, role_b)
                candidates.append((redundant, covering, 0, True))
            elif set_a < set_b:
                candidates.append((role_a, role_b, len(set_b - set_a), False))
            elif set_b < set_a:
                candidates.append((role_b, role_a, len(set_a - set_b), False))
        best_by_redundant: dict[str, tuple[str, int, bool]] = {}
        for redundant, covering, extras, exact in candidates:
            current = best_by_redundant.get(redundant)
            candidate_rank = (not exact, extras, -global_users.get(covering, 0), str(covering))
            if current is None:
                best_by_redundant[redundant] = (covering, extras, exact)
            else:
                current_rank = (
                    not current[2],
                    current[1],
                    -global_users.get(current[0], 0),
                    str(current[0]),
                )
                if candidate_rank < current_rank:
                    best_by_redundant[redundant] = (covering, extras, exact)
        for redundant, (covering, extras, exact) in best_by_redundant.items():
            covered_rows.append(
                {
                    "ID_USUARIO_ERP": user,
                    "ROL_POTENCIALMENTE_REDUNDANTE": names.get(redundant, redundant),
                    "ID_ROL_REDUNDANTE": redundant,
                    "CUBIERTO_POR_ROL": names.get(covering, covering),
                    "ID_ROL_COBERTURA": covering,
                    "COBERTURA_EXACTA": "SI" if exact else "NO",
                    "PRIVILEGIOS_EXTRA_DEL_ROL_COBERTURA": extras,
                }
            )
    return pd.DataFrame(covered_rows), pd.DataFrame(repeated_rows)


def build_role_mapping(
    inventory: Inventory, identical_roles: pd.DataFrame, low_use_limit: int = 1
) -> pd.DataFrame:
    summary = role_summary(inventory).copy()
    duplicate_noncanonical: set[str] = set()
    if not identical_roles.empty:
        for _, row in identical_roles.iterrows():
            choices = [
                (int(row["USUARIOS_A"]), str(row["ID_ROL_A"])),
                (int(row["USUARIOS_B"]), str(row["ID_ROL_B"])),
            ]
            canonical_index = 0 if choices[0] >= choices[1] else 1
            duplicate_noncanonical.add(
                str(row["ID_ROL_B"] if canonical_index == 0 else row["ID_ROL_A"])
            )

    def action(row: pd.Series) -> str:
        role_id = str(row["ID_ROL_ASIGNADO"])
        if row["AVISOS_INTEGRIDAD"] > 0:
            return "CORREGIR INTEGRIDAD ANTES DE MAPEAR"
        if row["PRIVILEGIOS"] == 0:
            return "BLOQUEAR Y REVISAR: SIN PRIVILEGIOS"
        if row["USUARIOS"] == 0:
            return "CANDIDATO A RETIRADA: SIN USUARIOS"
        if role_id in duplicate_noncanonical:
            return "CANDIDATO A FUSION: PRIVILEGIOS IDENTICOS"
        if row["NOMBRE_A_REVISAR"] or row["USUARIOS"] <= low_use_limit:
            return "REVISAR VIGENCIA"
        return "MANTENER 1:1 EN FASE INICIAL"

    summary["ACCION_PROPUESTA"] = summary.apply(action, axis=1)
    summary["GRUPO_OCI_PROPUESTO"] = summary["CODIGO_ROL"].map(
        lambda value: f"ERP_ROLE_{normalized_key(value)}"
    )
    summary["OWNER_NEGOCIO"] = ""
    summary["ESTADO_DECISION"] = "PENDIENTE"
    summary["NOTAS"] = ""
    return summary[
        [
            "ID_ROL_ASIGNADO",
            "CODIGO_ROL",
            "DESCRIPCION_ROL",
            "USUARIOS",
            "PRIVILEGIOS",
            "ITEMS_OPERACIONES",
            "FAMILIA_SUGERIDA",
            "ACCION_PROPUESTA",
            "GRUPO_OCI_PROPUESTO",
            "OWNER_NEGOCIO",
            "ESTADO_DECISION",
            "NOTAS",
        ]
    ]


def build_capability_mapping(inventory: Inventory) -> pd.DataFrame:
    catalog = inventory.privilege_catalog.copy()
    catalog = catalog[catalog["ID_PRIVILEGIO_REFERENCIADO"].map(clean_text).ne("")]
    catalog = catalog.drop_duplicates("ID_PRIVILEGIO_REFERENCIADO")
    catalog["CAPACIDAD_SUGERIDA"] = catalog.apply(
        lambda row: suggest_capability(
            row["CODIGO_PRIVILEGIO"], row["DESCRIPCION_PRIVILEGIO"]
        ),
        axis=1,
    )
    catalog["DESTINO_PROPUESTO"] = "MANTENER EN ERP"
    catalog["OWNER_NEGOCIO"] = ""
    catalog["ESTADO_DECISION"] = "PENDIENTE"
    catalog["NOTAS"] = ""
    return catalog[
        [
            "ID_PRIVILEGIO_REFERENCIADO",
            "CODIGO_PRIVILEGIO",
            "DESCRIPCION_PRIVILEGIO",
            "TIPO_PRIVILEGIO",
            "CAPACIDAD_SUGERIDA",
            "DESTINO_PROPUESTO",
            "OWNER_NEGOCIO",
            "ESTADO_DECISION",
            "NOTAS",
        ]
    ]
