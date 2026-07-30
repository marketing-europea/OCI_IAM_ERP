from __future__ import annotations

import io
import json
import re
import unicodedata
import zipfile

import pandas as pd
import plotly.express as px
import streamlit as st


# ============================================================
# CONFIGURACIÓN GENERAL
# ============================================================

st.set_page_config(
    page_title="Mapa ERP → OCI IAM",
    layout="wide",
    initial_sidebar_state="expanded",
)

CUSTOM_USER_URN = (
    "urn:ietf:params:scim:schemas:idcs:extension:custom:User"
)

DOCUMENTACION_OCI = {
    "Esquema SCIM de OCI IAM":
        "https://docs.oracle.com/en-us/iaas/Content/Identity/"
        "api-getstarted/OCISSchema.htm",

    "Atributos personalizados":
        "https://docs.oracle.com/en-us/iaas/Content/Identity/"
        "api-getstarted/schemacustomization.htm",

    "Claims personalizados":
        "https://docs.oracle.com/en-us/iaas/Content/Identity/"
        "api-getstarted/custom-claims-token.htm",

    "Scopes OAuth/OIDC":
        "https://docs.oracle.com/en-us/iaas/Content/Identity/"
        "api-getstarted/Scopes.htm",

    "Gestión de grupos":
        "https://docs.oracle.com/en-us/iaas/Content/Identity/"
        "groups/managinggroups.htm",
}


# ============================================================
# REGLAS ORIENTATIVAS
# ============================================================

REGLAS_FAMILIA = [
    (
        "SINIESTROS",
        r"SINIEST|RESERV|PRESTACION|PROFESIONAL|CUADRO_MED|URGEN",
    ),
    (
        "MEDIADOR",
        r"MEDIADOR|TESTER.?MED|RED_AGENT|ASESOR|COLABORADOR_MED",
    ),
    (
        "COMERCIAL",
        r"COMERCIAL|CRM|CLIENTE|AGENDA|SUSCRIPTOR",
    ),
    (
        "CONTABILIDAD_FINANZAS",
        r"COBRO|RECIBO|LIQUID|PAGO|FINAN|COMISION|REAJUST",
    ),
    (
        "POLIZAS_PRODUCTO",
        r"POLIZ|TARIFIC|EMITIR|PRODUC|D100|D300|D400|D475|D490|D600|TAR75",
    ),
    (
        "ADMINISTRACION",
        r"ADMINISTR|SERVICIOS_CENTRALES|CONTROL.?GESTION",
    ),
    (
        "TECNOLOGIA",
        r"DESARROLLO|INTEGRACION|SAP|FIRMA_DIGITAL",
    ),
    (
        "REASEGURO_ACTUARIAL",
        r"REASEGURO|ACTUARIO",
    ),
]

REGLAS_CAPACIDAD = [
    ("CONSULTAR", r"CONSULT"),
    ("TARIFICAR", r"TARIFIC|SOLOTAR|TAR_Y"),
    ("EMITIR", r"EMIT|EMI_"),
    ("ANULAR", r"ANUL"),
    ("GESTIONAR_COBROS", r"COBRO|RECIBO"),
    ("GESTIONAR_LIQUIDACIONES", r"LIQUID"),
    ("GESTIONAR_COMISIONES", r"COMISION"),
    ("GESTIONAR_SINIESTROS", r"SINIEST"),
    ("MODIFICAR_RESERVAS", r"RESERVAS_MODIFICACION"),
    ("CIERRE_MEDIADOR", r"CONCIERRE|CIERREMEDIADOR"),
    ("GESTIONAR_POLIZAS", r"GESTION_POLIZAS"),
    ("ADMINISTRAR", r"ADMINISTR"),
]

FAMILIAS_DISPONIBLES = [
    "MEDIADOR",
    "SINIESTROS",
    "COMERCIAL",
    "CONTABILIDAD_FINANZAS",
    "POLIZAS_PRODUCTO",
    "ADMINISTRACION",
    "TECNOLOGIA",
    "REASEGURO_ACTUARIAL",
    "POR_CLASIFICAR",
]

CAPACIDADES_DISPONIBLES = [
    "SIN_CLASIFICAR",
    "CONSULTAR",
    "TARIFICAR",
    "EMITIR",
    "MODIFICAR",
    "ANULAR",
    "CERRAR",
    "GESTIONAR_COBROS",
    "GESTIONAR_LIQUIDACIONES",
    "GESTIONAR_COMISIONES",
    "GESTIONAR_SINIESTROS",
    "MODIFICAR_RESERVAS",
    "CIERRE_MEDIADOR",
    "GESTIONAR_POLIZAS",
    "SUPERVISAR",
    "ADMINISTRAR",
    "NO_MIGRAR_A_OCI",
]


# ============================================================
# ATRIBUTOS PROPUESTOS
# ============================================================

ATRIBUTOS_PROPUESTOS = [
    {
        "origen_erp": "ID_DUSUARIOS_FK",
        "destino_oci": "externalId",
        "esquema": "SCIM core",
        "tipo_oci": "string",
        "obligatorio": True,
        "claim_oidc": "erp_user_id",
        "estado": "Propuesto",
        "observacion":
            "Identificador estable: ERP:<ID_DUSUARIOS_FK>.",
    },
    {
        "origen_erp": "USUARCOD",
        "destino_oci": "userName",
        "esquema": "SCIM core",
        "tipo_oci": "string",
        "obligatorio": True,
        "claim_oidc": "preferred_username",
        "estado": "Pendiente de fichero",
        "observacion":
            "No está en los CSV actuales. Comprobar unicidad.",
    },
    {
        "origen_erp": "EMAIL",
        "destino_oci": "emails[type=work].value",
        "esquema": "SCIM core",
        "tipo_oci": "complex",
        "obligatorio": True,
        "claim_oidc": "email",
        "estado": "Pendiente de fichero",
        "observacion":
            "No está en los CSV actuales.",
    },
    {
        "origen_erp": "NOMBRE",
        "destino_oci": "name.givenName",
        "esquema": "SCIM core",
        "tipo_oci": "string",
        "obligatorio": False,
        "claim_oidc": "given_name",
        "estado": "Pendiente de fichero",
        "observacion":
            "Usar el atributo estándar de SCIM.",
    },
    {
        "origen_erp": "APELLIDOS",
        "destino_oci": "name.familyName",
        "esquema": "SCIM core",
        "tipo_oci": "string",
        "obligatorio": False,
        "claim_oidc": "family_name",
        "estado": "Pendiente de fichero",
        "observacion":
            "Usar el atributo estándar de SCIM.",
    },
    {
        "origen_erp": "ESTADO_USUARIO",
        "destino_oci": "active",
        "esquema": "SCIM core",
        "tipo_oci": "boolean",
        "obligatorio": True,
        "claim_oidc": "",
        "estado": "Pendiente de fichero",
        "observacion":
            "Definir reglas de alta, suspensión, baja y reactivación.",
    },
    {
        "origen_erp": "TIPO_USUARIO",
        "destino_oci": "erpTipoUsuario",
        "esquema": "Custom User",
        "tipo_oci": "string",
        "obligatorio": False,
        "claim_oidc": "erp_tipo_usuario",
        "estado": "Propuesto",
        "observacion":
            "Recomendable definir un catálogo cerrado de valores.",
    },
    {
        "origen_erp": "NIVEL_TRANSACCIONAL",
        "destino_oci": "erpNivel",
        "esquema": "Custom User",
        "tipo_oci": "string",
        "obligatorio": False,
        "claim_oidc": "erp_nivel",
        "estado": "Propuesto",
        "observacion":
            "Tratarlo como código si no se realizan cálculos.",
    },
    {
        "origen_erp": "prefijo(USUARCOD)",
        "destino_oci": "erpCodigoMediador",
        "esquema": "Custom User",
        "tipo_oci": "string",
        "obligatorio": False,
        "claim_oidc": "erp_codigo_mediador",
        "estado": "Propuesto",
        "observacion":
            "Mantener ceros iniciales y formalizar la regla de extracción.",
    },
    {
        "origen_erp": "DELEGACION",
        "destino_oci": "erpDelegacion",
        "esquema": "Custom User",
        "tipo_oci": "string",
        "obligatorio": False,
        "claim_oidc": "erp_delegacion",
        "estado": "Propuesto",
        "observacion":
            "Revisar si encaja mejor en SCIM Enterprise department.",
    },
    {
        "origen_erp": "EMPRESA",
        "destino_oci": "erpEmpresa",
        "esquema": "Custom User",
        "tipo_oci": "string",
        "obligatorio": False,
        "claim_oidc": "erp_empresa",
        "estado": "Propuesto",
        "observacion":
            "Revisar si encaja mejor en SCIM Enterprise organization.",
    },
]


# ============================================================
# ESTILO
# ============================================================

st.markdown(
    """
    <style>
        .stApp {
            background:
                linear-gradient(135deg, #07131f 0%, #0b1d2b 50%, #102839 100%);
        }

        [data-testid="stSidebar"] {
            background: #081722;
            border-right: 1px solid #17394c;
        }

        .cabecera {
            padding: 1.7rem 2rem;
            margin-bottom: 1rem;
            border: 1px solid #1d4c64;
            border-radius: 18px;
            background:
                linear-gradient(
                    120deg,
                    rgba(18, 59, 78, 0.95),
                    rgba(8, 24, 36, 0.95)
                );
        }

        .cabecera h1 {
            margin: 0 0 0.4rem 0;
        }

        .cabecera p {
            margin: 0;
            color: #bad0dc;
        }

        .aviso {
            padding: 1rem 1.2rem;
            margin: 0.6rem 0 1rem 0;
            border-left: 4px solid #2dd4bf;
            border-radius: 8px;
            background: #0a2230;
        }

        .aviso-amarillo {
            border-left-color: #f59e0b;
            background: #2a2112;
        }

        div[data-testid="stMetric"] {
            padding: 1rem;
            border: 1px solid #173f52;
            border-radius: 14px;
            background: #0c2432;
        }

        div[data-testid="stMetricValue"] {
            color: #5eead4;
        }
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class="cabecera">
        <h1>🔐 Mapa de identidad ERP → OCI IAM</h1>
        <p>
            Analiza perfiles y funciones, compara variantes, diseña atributos
            SCIM y simula la información que recibirá el ERP mediante OIDC.
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# FUNCIONES AUXILIARES
# ============================================================

def normalizar_texto(valor: object) -> str:
    texto = unicodedata.normalize("NFKD", str(valor or ""))
    texto = "".join(
        caracter
        for caracter in texto
        if not unicodedata.combining(caracter)
    )
    texto = texto.upper()
    texto = re.sub(r"[^A-Z0-9]+", "_", texto)
    return texto.strip("_")


def leer_csv_subido(archivo) -> pd.DataFrame:
    """
    Lee el archivo exclusivamente en memoria.

    No se guarda en disco y no se envía a servicios externos.
    """
    contenido = archivo.getvalue()

    for encoding in ("utf-8-sig", "utf-8", "cp1252", "latin-1"):
        try:
            return pd.read_csv(
                io.BytesIO(contenido),
                encoding=encoding,
            )
        except UnicodeDecodeError:
            continue

    raise ValueError(
        f"No se pudo detectar la codificación de {archivo.name}"
    )


def validar_columnas(
    dataframe: pd.DataFrame,
    columnas_obligatorias: set[str],
    nombre_fichero: str,
) -> None:
    columnas_faltantes = (
        columnas_obligatorias - set(dataframe.columns)
    )

    if columnas_faltantes:
        faltantes = ", ".join(sorted(columnas_faltantes))
        raise ValueError(
            f"{nombre_fichero}: faltan las columnas {faltantes}"
        )


def proponer_familia(nombre_rol: str) -> tuple[str, str]:
    nombre = normalizar_texto(nombre_rol)

    coincidencias = [
        familia
        for familia, patron in REGLAS_FAMILIA
        if re.search(patron, nombre)
    ]

    if not coincidencias:
        return "POR_CLASIFICAR", "Baja"

    if len(coincidencias) == 1:
        return coincidencias[0], "Alta"

    return coincidencias[0], "Media"


def proponer_capacidades(nombre_rol: str) -> list[str]:
    nombre = normalizar_texto(nombre_rol)

    return [
        capacidad
        for capacidad, patron in REGLAS_CAPACIDAD
        if re.search(patron, nombre)
    ]


def crear_nombre_grupo_oci(nombre_rol: str) -> str:
    nombre = normalizar_texto(nombre_rol)
    return f"ERP_ROLE_{nombre[:85]}"


def dataframe_csv(dataframe: pd.DataFrame) -> bytes:
    return dataframe.to_csv(
        index=False
    ).encode("utf-8-sig")


def crear_json_esquema_personalizado(
    atributos: pd.DataFrame,
) -> dict:
    personalizados = atributos[
        atributos["esquema"] == "Custom User"
    ]

    definiciones = []

    for fila in personalizados.to_dict("records"):
        definiciones.append(
            {
                "name": fila["destino_oci"],
                "idcsDisplayName": fila["destino_oci"],
                "description": fila["observacion"],
                "required": bool(fila["obligatorio"]),
                "type": "string",
                "idcsMinLength": 1,
                "idcsMaxLength": 255,
                "idcsAuditable": True,
                "returned": "default",
                "mutability": "readWrite",
                "idcsSearchable": True,
                "multiValued": False,
            }
        )

    return {
        "_aviso": (
            "BORRADOR. Revisar antes de aplicarlo en OCI."
        ),
        "_endpoint": (
            f"/admin/v1/Schemas/{CUSTOM_USER_URN}"
        ),
        "schemas": [
            "urn:ietf:params:scim:api:messages:2.0:PatchOp"
        ],
        "Operations": [
            {
                "op": "add",
                "path": "attributes",
                "value": definiciones,
            }
        ],
    }


def crear_json_claims(atributos: pd.DataFrame) -> list[dict]:
    resultado = []

    for fila in atributos.to_dict("records"):
        claim = str(fila.get("claim_oidc", "") or "").strip()

        if not claim:
            continue

        if "/" in claim:
            continue

        destino = fila["destino_oci"]

        if fila["esquema"] == "Custom User":
            expresion = (
                f"$user.{CUSTOM_USER_URN}.{destino}"
            )
        elif destino == "externalId":
            expresion = "$user.externalId"
        else:
            continue

        resultado.append(
            {
                "_aviso": "BORRADOR. Revisar antes de aplicar.",
                "schemas": [
                    "urn:ietf:params:scim:schemas:"
                    "oracle:idcs:CustomClaim"
                ],
                "name": claim,
                "value": expresion,
                "expression": True,
                "mode": "always",
                "tokenType": "BOTH",
                "allScopes": True,
            }
        )

    return resultado


def crear_paquete_exportacion(
    mapeo_roles: pd.DataFrame,
    mapeo_funciones: pd.DataFrame,
    mapeo_atributos: pd.DataFrame,
    informe_calidad: dict,
) -> bytes:
    memoria = io.BytesIO()

    with zipfile.ZipFile(
        memoria,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
    ) as archivo_zip:
        archivo_zip.writestr(
            "mapeo_roles_oci.csv",
            dataframe_csv(mapeo_roles),
        )

        archivo_zip.writestr(
            "mapeo_funciones_capacidades.csv",
            dataframe_csv(mapeo_funciones),
        )

        archivo_zip.writestr(
            "mapeo_atributos_scim.csv",
            dataframe_csv(mapeo_atributos),
        )

        archivo_zip.writestr(
            "oci_custom_schema_patch.json",
            json.dumps(
                crear_json_esquema_personalizado(
                    mapeo_atributos
                ),
                ensure_ascii=False,
                indent=2,
            ),
        )

        archivo_zip.writestr(
            "oci_custom_claims.json",
            json.dumps(
                crear_json_claims(mapeo_atributos),
                ensure_ascii=False,
                indent=2,
            ),
        )

        archivo_zip.writestr(
            "informe_calidad.json",
            json.dumps(
                informe_calidad,
                ensure_ascii=False,
                indent=2,
            ),
        )

        archivo_zip.writestr(
            "LEEME.txt",
            """
MAPEO ERP → OCI IAM

Los archivos de este paquete son borradores de diseño.

No deben aplicarse directamente en producción.

Modelo propuesto:

1. externalId enlaza al usuario OCI con su identificador ERP.
2. Los atributos organizativos se guardan en SCIM.
3. Los roles ERP se representan inicialmente como grupos OCI.
4. Las funciones ERP se clasifican en capacidades comprensibles.
5. El ERP sigue controlando menús, operaciones y reglas de negocio.
6. La migración debe hacerse de forma progresiva y reversible.

Antes del piloto hacen falta:

- Maestro completo de usuarios.
- Catálogo descriptivo de funciones.
- Validación de los propietarios funcionales.
- Revisión de segregación de funciones.
- Pruebas de equivalencia antes/después.
            """.strip(),
        )

    return memoria.getvalue()


# ============================================================
# CARGA MANUAL DE LOS CSV
# ============================================================

with st.sidebar:
    st.header("📁 Cargar inventarios")

    st.caption(
        "Los archivos se procesan en memoria durante la sesión."
    )

    archivo_usuarios_roles = st.file_uploader(
        "DROLUSERpro.csv — usuario ↔ rol",
        type=["csv"],
        key="archivo_usuarios_roles",
    )

    archivo_roles_funciones = st.file_uploader(
        "DROLFUNCpro.csv — rol ↔ función",
        type=["csv"],
        key="archivo_roles_funciones",
    )

    archivo_roles = st.file_uploader(
        "DROLESpro.csv — catálogo de roles",
        type=["csv"],
        key="archivo_roles",
    )

    st.divider()

    st.markdown(
        """
        **Lectura de resultados**

        🟢 Observado: procede del ERP.

        🟠 Inferido: sugerencia automática.

        ⚪ Pendiente: necesita validación.
        """
    )

    st.divider()

    st.subheader("Documentación oficial")

    for titulo, enlace in DOCUMENTACION_OCI.items():
        st.markdown(f"[↗ {titulo}]({enlace})")


archivos_completos = all(
    [
        archivo_usuarios_roles,
        archivo_roles_funciones,
        archivo_roles,
    ]
)

if not archivos_completos:
    st.info(
        "Sube los tres CSV desde el panel lateral para comenzar."
    )

    st.markdown(
        """
        <div class="aviso">
            <b>Privacidad:</b> esta aplicación no contiene copias de
            los CSV. Los archivos sólo se leen cuando los seleccionas
            desde la pantalla.
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.stop()


# ============================================================
# LECTURA Y VALIDACIÓN
# ============================================================

try:
    usuarios_roles = leer_csv_subido(
        archivo_usuarios_roles
    )

    roles_funciones = leer_csv_subido(
        archivo_roles_funciones
    )

    roles = leer_csv_subido(
        archivo_roles
    )

    for dataframe in (
        usuarios_roles,
        roles_funciones,
        roles,
    ):
        dataframe.columns = [
            str(columna).strip().upper()
            for columna in dataframe.columns
        ]

    validar_columnas(
        usuarios_roles,
        {
            "ID_DUSUARIOS_FK",
            "ID_DROLES_FK",
        },
        "DROLUSERpro.csv",
    )

    validar_columnas(
        roles_funciones,
        {
            "ID_DROLES_FK",
            "ID_DFUNCION_FK",
        },
        "DROLFUNCpro.csv",
    )

    validar_columnas(
        roles,
        {
            "ID_DROLES",
            "CODIGROL",
        },
        "DROLESpro.csv",
    )

except Exception as error:
    st.error(f"No se pudieron leer los archivos: {error}")
    st.stop()


# Convertimos los identificadores a valores numéricos.

usuarios_roles["ID_DUSUARIOS_FK"] = pd.to_numeric(
    usuarios_roles["ID_DUSUARIOS_FK"],
    errors="coerce",
).astype("Int64")

usuarios_roles["ID_DROLES_FK"] = pd.to_numeric(
    usuarios_roles["ID_DROLES_FK"],
    errors="coerce",
).astype("Int64")

roles_funciones["ID_DROLES_FK"] = pd.to_numeric(
    roles_funciones["ID_DROLES_FK"],
    errors="coerce",
).astype("Int64")

roles_funciones["ID_DFUNCION_FK"] = pd.to_numeric(
    roles_funciones["ID_DFUNCION_FK"],
    errors="coerce",
).astype("Int64")

roles["ID_DROLES"] = pd.to_numeric(
    roles["ID_DROLES"],
    errors="coerce",
).astype("Int64")


# ============================================================
# CONSTRUCCIÓN DEL MODELO
# ============================================================

conteo_usuarios = usuarios_roles.groupby(
    "ID_DROLES_FK"
)["ID_DUSUARIOS_FK"].nunique()

conteo_funciones = roles_funciones.groupby(
    "ID_DROLES_FK"
)["ID_DFUNCION_FK"].nunique()

catalogo_roles = roles.copy()

catalogo_roles["usuarios"] = (
    catalogo_roles["ID_DROLES"]
    .map(conteo_usuarios)
    .fillna(0)
    .astype(int)
)

catalogo_roles["funciones"] = (
    catalogo_roles["ID_DROLES"]
    .map(conteo_funciones)
    .fillna(0)
    .astype(int)
)

propuestas_familia = catalogo_roles[
    "CODIGROL"
].apply(proponer_familia)

catalogo_roles["familia_propuesta"] = (
    propuestas_familia.str[0]
)

catalogo_roles["confianza"] = (
    propuestas_familia.str[1]
)

catalogo_roles["capacidades_por_nombre"] = (
    catalogo_roles["CODIGROL"].apply(
        lambda valor: ", ".join(
            proponer_capacidades(valor)
        )
    )
)

catalogo_roles["grupo_oci_propuesto"] = (
    catalogo_roles["CODIGROL"].apply(
        crear_nombre_grupo_oci
    )
)

catalogo_roles["estado_decision"] = "Pendiente"
catalogo_roles["observacion"] = ""


# Funciones asociadas a cada rol.

funciones_por_rol = {
    int(id_rol): set(
        grupo["ID_DFUNCION_FK"]
        .dropna()
        .astype(int)
    )
    for id_rol, grupo in roles_funciones.groupby(
        "ID_DROLES_FK"
    )
}


# ============================================================
# INFORME DE CALIDAD
# ============================================================

informe_calidad = {
    "usuarios_unicos": int(
        usuarios_roles["ID_DUSUARIOS_FK"].nunique()
    ),
    "roles_catalogo": int(
        roles["ID_DROLES"].nunique()
    ),
    "roles_asignados": int(
        usuarios_roles["ID_DROLES_FK"].nunique()
    ),
    "funciones_unicas": int(
        roles_funciones["ID_DFUNCION_FK"].nunique()
    ),
    "asignaciones_usuario_rol": int(
        len(usuarios_roles)
    ),
    "asignaciones_rol_funcion": int(
        len(roles_funciones)
    ),
    "roles_sin_usuarios": int(
        (
            ~roles["ID_DROLES"].isin(
                usuarios_roles["ID_DROLES_FK"]
            )
        ).sum()
    ),
    "roles_sin_funciones": int(
        (
            ~roles["ID_DROLES"].isin(
                roles_funciones["ID_DROLES_FK"]
            )
        ).sum()
    ),
    "asignaciones_con_rol_desconocido": int(
        (
            ~usuarios_roles["ID_DROLES_FK"].isin(
                roles["ID_DROLES"]
            )
        ).sum()
    ),
    "duplicados_usuario_rol": int(
        usuarios_roles.duplicated(
            [
                "ID_DUSUARIOS_FK",
                "ID_DROLES_FK",
            ]
        ).sum()
    ),
    "duplicados_rol_funcion": int(
        roles_funciones.duplicated(
            [
                "ID_DROLES_FK",
                "ID_DFUNCION_FK",
            ]
        ).sum()
    ),
}


# ============================================================
# ESTADO EDITABLE DE STREAMLIT
# ============================================================

if "mapeo_roles" not in st.session_state:
    st.session_state.mapeo_roles = catalogo_roles[
        [
            "ID_DROLES",
            "CODIGROL",
            "usuarios",
            "funciones",
            "familia_propuesta",
            "confianza",
            "capacidades_por_nombre",
            "grupo_oci_propuesto",
            "estado_decision",
            "observacion",
        ]
    ].copy()


if "mapeo_funciones" not in st.session_state:
    ids_funciones = sorted(
        roles_funciones[
            "ID_DFUNCION_FK"
        ]
        .dropna()
        .astype(int)
        .unique()
    )

    st.session_state.mapeo_funciones = pd.DataFrame(
        {
            "ID_DFUNCION": ids_funciones,
            "codigo_funcion": "",
            "descripcion_funcion": "",
            "capacidad_objetivo": "SIN_CLASIFICAR",
            "criticidad": "Por revisar",
            "propietario_funcional": "",
            "observacion": "",
        }
    )


if "mapeo_atributos" not in st.session_state:
    st.session_state.mapeo_atributos = pd.DataFrame(
        ATRIBUTOS_PROPUESTOS
    )


# ============================================================
# PESTAÑAS PRINCIPALES
# ============================================================

(
    tab_resumen,
    tab_roles,
    tab_comparacion,
    tab_mapeo,
    tab_oci,
    tab_token,
    tab_exportar,
) = st.tabs(
    [
        "Resumen",
        "Explorar roles",
        "Comparar variantes",
        "Taller de mapeo",
        "Diseño OCI",
        "Simular token",
        "Exportar",
    ]
)


# ============================================================
# RESUMEN
# ============================================================

with tab_resumen:
    columnas = st.columns(5)

    columnas[0].metric(
        "Usuarios",
        informe_calidad["usuarios_unicos"],
    )

    columnas[1].metric(
        "Roles",
        informe_calidad["roles_catalogo"],
    )

    columnas[2].metric(
        "Roles asignados",
        informe_calidad["roles_asignados"],
    )

    columnas[3].metric(
        "Funciones",
        informe_calidad["funciones_unicas"],
    )

    columnas[4].metric(
        "Asignaciones",
        informe_calidad["asignaciones_usuario_rol"],
    )

    st.markdown(
        """
        <div class="aviso aviso-amarillo">
            <b>Límite actual:</b> los archivos contienen las relaciones
            usuario–rol y rol–función, pero no contienen el maestro
            completo de usuarios ni la descripción de las funciones.
            La aplicación no inventa esos datos.
        </div>
        """,
        unsafe_allow_html=True,
    )

    izquierda, derecha = st.columns(2)

    with izquierda:
        st.subheader("Roles con más usuarios")

        roles_principales = (
            catalogo_roles
            .nlargest(15, "usuarios")
            .sort_values("usuarios")
        )

        grafico = px.bar(
            roles_principales,
            x="usuarios",
            y="CODIGROL",
            orientation="h",
            color="funciones",
            color_continuous_scale="Tealgrn",
            labels={
                "usuarios": "Usuarios",
                "CODIGROL": "",
                "funciones": "Funciones",
            },
        )

        grafico.update_layout(height=520)

        st.plotly_chart(
            grafico,
            use_container_width=True,
        )

    with derecha:
        st.subheader("Usuarios frente a funciones")

        dispersion = px.scatter(
            catalogo_roles,
            x="usuarios",
            y="funciones",
            color="familia_propuesta",
            hover_name="CODIGROL",
            size="usuarios",
            size_max=40,
            labels={
                "usuarios": "Usuarios",
                "funciones": "Funciones",
            },
        )

        dispersion.update_layout(height=410)

        st.plotly_chart(
            dispersion,
            use_container_width=True,
        )

        st.subheader("Calidad de los datos")

        tabla_calidad = pd.DataFrame(
            [
                {
                    "control": "Roles sin usuarios",
                    "resultado":
                        informe_calidad["roles_sin_usuarios"],
                },
                {
                    "control": "Roles sin funciones",
                    "resultado":
                        informe_calidad["roles_sin_funciones"],
                },
                {
                    "control": "Asignaciones a rol desconocido",
                    "resultado":
                        informe_calidad[
                            "asignaciones_con_rol_desconocido"
                        ],
                },
                {
                    "control": "Duplicados usuario–rol",
                    "resultado":
                        informe_calidad[
                            "duplicados_usuario_rol"
                        ],
                },
                {
                    "control": "Duplicados rol–función",
                    "resultado":
                        informe_calidad[
                            "duplicados_rol_funcion"
                        ],
                },
            ]
        )

        st.dataframe(
            tabla_calidad,
            hide_index=True,
            use_container_width=True,
        )


# ============================================================
# EXPLORACIÓN DE ROLES
# ============================================================

with tab_roles:
    st.subheader("Ficha de un rol")

    nombres_roles = (
        catalogo_roles["CODIGROL"]
        .astype(str)
        .sort_values()
        .tolist()
    )

    nombre_rol_seleccionado = st.selectbox(
        "Selecciona un rol",
        nombres_roles,
    )

    fila_rol = catalogo_roles[
        catalogo_roles["CODIGROL"].astype(str)
        == nombre_rol_seleccionado
    ].iloc[0]

    id_rol_seleccionado = int(
        fila_rol["ID_DROLES"]
    )

    columnas = st.columns(4)

    columnas[0].metric(
        "ID del rol",
        id_rol_seleccionado,
    )

    columnas[1].metric(
        "Usuarios",
        int(fila_rol["usuarios"]),
    )

    columnas[2].metric(
        "Funciones",
        int(fila_rol["funciones"]),
    )

    columnas[3].metric(
        "Familia sugerida",
        fila_rol["familia_propuesta"],
    )

    izquierda, derecha = st.columns(2)

    with izquierda:
        st.markdown("#### Usuarios asignados")

        usuarios_del_rol = (
            usuarios_roles[
                usuarios_roles["ID_DROLES_FK"]
                == id_rol_seleccionado
            ][["ID_DUSUARIOS_FK"]]
            .drop_duplicates()
            .sort_values("ID_DUSUARIOS_FK")
        )

        st.dataframe(
            usuarios_del_rol,
            hide_index=True,
            use_container_width=True,
            height=400,
        )

    with derecha:
        st.markdown("#### Funciones asignadas")

        funciones_del_rol = (
            roles_funciones[
                roles_funciones["ID_DROLES_FK"]
                == id_rol_seleccionado
            ][["ID_DFUNCION_FK"]]
            .drop_duplicates()
        )

        funciones_descritas = funciones_del_rol.merge(
            st.session_state.mapeo_funciones,
            left_on="ID_DFUNCION_FK",
            right_on="ID_DFUNCION",
            how="left",
        )

        st.dataframe(
            funciones_descritas[
                [
                    "ID_DFUNCION_FK",
                    "codigo_funcion",
                    "descripcion_funcion",
                    "capacidad_objetivo",
                ]
            ],
            hide_index=True,
            use_container_width=True,
            height=400,
        )

    capacidades_sugeridas = (
        fila_rol["capacidades_por_nombre"]
        or "No se pudo sugerir ninguna"
    )

    st.info(
        "Capacidades sugeridas por el nombre del rol: "
        f"{capacidades_sugeridas}. "
        "Esta sugerencia requiere validación funcional."
    )


# ============================================================
# COMPARACIÓN
# ============================================================

with tab_comparacion:
    st.subheader("Comparar dos perfiles")

    columna_a, columna_b = st.columns(2)

    nombre_rol_a = columna_a.selectbox(
        "Rol A",
        nombres_roles,
        key="comparador_rol_a",
    )

    indice_b = (
        1 if len(nombres_roles) > 1 else 0
    )

    nombre_rol_b = columna_b.selectbox(
        "Rol B",
        nombres_roles,
        index=indice_b,
        key="comparador_rol_b",
    )

    tabla_ids_roles = catalogo_roles.set_index(
        "CODIGROL"
    )["ID_DROLES"].to_dict()

    id_rol_a = int(
        tabla_ids_roles[nombre_rol_a]
    )

    id_rol_b = int(
        tabla_ids_roles[nombre_rol_b]
    )

    funciones_a = funciones_por_rol.get(
        id_rol_a,
        set(),
    )

    funciones_b = funciones_por_rol.get(
        id_rol_b,
        set(),
    )

    funciones_comunes = funciones_a & funciones_b
    solo_a = funciones_a - funciones_b
    solo_b = funciones_b - funciones_a
    union = funciones_a | funciones_b

    similitud = (
        len(funciones_comunes) / len(union)
        if union
        else 1.0
    )

    columnas = st.columns(4)

    columnas[0].metric(
        "Similitud Jaccard",
        f"{similitud:.1%}",
    )

    columnas[1].metric(
        "Funciones comunes",
        len(funciones_comunes),
    )

    columnas[2].metric(
        "Sólo en el rol A",
        len(solo_a),
    )

    columnas[3].metric(
        "Sólo en el rol B",
        len(solo_b),
    )

    diferencias = pd.DataFrame(
        [
            {
                "ID_DFUNCION": funcion,
                "presencia": f"Sólo {nombre_rol_a}",
            }
            for funcion in sorted(solo_a)
        ]
        + [
            {
                "ID_DFUNCION": funcion,
                "presencia": f"Sólo {nombre_rol_b}",
            }
            for funcion in sorted(solo_b)
        ]
        + [
            {
                "ID_DFUNCION": funcion,
                "presencia": "Común",
            }
            for funcion in sorted(funciones_comunes)
        ]
    )

    diferencias = diferencias.merge(
        st.session_state.mapeo_funciones,
        on="ID_DFUNCION",
        how="left",
    )

    opciones_presencia = (
        diferencias["presencia"]
        .drop_duplicates()
        .tolist()
    )

    seleccion_presencia = st.multiselect(
        "Elementos que se mostrarán",
        opciones_presencia,
        default=[
            opcion
            for opcion in opciones_presencia
            if opcion != "Común"
        ],
    )

    st.dataframe(
        diferencias[
            diferencias["presencia"].isin(
                seleccion_presencia
            )
        ][
            [
                "ID_DFUNCION",
                "presencia",
                "descripcion_funcion",
                "capacidad_objetivo",
            ]
        ],
        hide_index=True,
        use_container_width=True,
        height=430,
    )

    st.warning(
        "Una similitud alta no significa que los roles puedan "
        "fusionarse. Las diferencias deben explicarse y aprobarse."
    )


# ============================================================
# TALLER DE MAPEO
# ============================================================

with tab_mapeo:
    st.subheader(
        "1. Rol ERP → familia y grupo OCI"
    )

    st.session_state.mapeo_roles = st.data_editor(
        st.session_state.mapeo_roles,
        hide_index=True,
        use_container_width=True,
        height=430,
        disabled=[
            "ID_DROLES",
            "CODIGROL",
            "usuarios",
            "funciones",
            "confianza",
            "capacidades_por_nombre",
        ],
        column_config={
            "familia_propuesta":
                st.column_config.SelectboxColumn(
                    "familia_objetivo",
                    options=FAMILIAS_DISPONIBLES,
                ),

            "estado_decision":
                st.column_config.SelectboxColumn(
                    "estado_decision",
                    options=[
                        "Pendiente",
                        "Validado",
                        "Excepción",
                        "Descartar",
                    ],
                ),
        },
        key="editor_roles",
    )

    st.subheader(
        "2. Función ERP → capacidad"
    )

    st.markdown(
        """
        <div class="aviso aviso-amarillo">
            Los CSV sólo contienen identificadores de función.
            Introduce el código y la descripción del catálogo
            funcional antes de tomar decisiones definitivas.
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.session_state.mapeo_funciones = st.data_editor(
        st.session_state.mapeo_funciones,
        hide_index=True,
        use_container_width=True,
        height=440,
        disabled=["ID_DFUNCION"],
        column_config={
            "capacidad_objetivo":
                st.column_config.SelectboxColumn(
                    "capacidad_objetivo",
                    options=CAPACIDADES_DISPONIBLES,
                ),

            "criticidad":
                st.column_config.SelectboxColumn(
                    "criticidad",
                    options=[
                        "Por revisar",
                        "Baja",
                        "Media",
                        "Alta",
                        "Segregación",
                    ],
                ),
        },
        key="editor_funciones",
    )

    porcentaje_clasificado = (
        st.session_state.mapeo_funciones[
            "capacidad_objetivo"
        ]
        .ne("SIN_CLASIFICAR")
        .mean()
    )

    st.progress(
        float(porcentaje_clasificado),
        text=(
            "Funciones clasificadas: "
            f"{porcentaje_clasificado:.1%}"
        ),
    )

    st.subheader(
        "3. Atributos ERP → SCIM y OIDC"
    )

    st.session_state.mapeo_atributos = st.data_editor(
        st.session_state.mapeo_atributos,
        hide_index=True,
        use_container_width=True,
        height=430,
        column_config={
            "obligatorio":
                st.column_config.CheckboxColumn(
                    "obligatorio"
                ),

            "estado":
                st.column_config.SelectboxColumn(
                    "estado",
                    options=[
                        "Propuesto",
                        "Validado",
                        "Pendiente de fichero",
                        "Descartar",
                    ],
                ),
        },
        key="editor_atributos",
    )


# ============================================================
# DISEÑO OCI
# ============================================================

with tab_oci:
    st.subheader(
        "Arquitectura propuesta"
    )

    st.markdown(
        """
        <div class="aviso">
            <b>Asignación:</b> grupos OCI ERP_ROLE_* para reproducir
            inicialmente los perfiles actuales.<br><br>

            <b>Atributos:</b> SCIM core o Enterprise cuando exista
            un atributo estándar; Custom User únicamente cuando sea
            necesario.<br><br>

            <b>Entrega al ERP:</b> token OIDC y, si es necesario,
            consulta al endpoint userinfo.<br><br>

            <b>Decisión final:</b> el ERP conserva la traducción a
            funciones, menús, operaciones y reglas de negocio.
        </div>
        """,
        unsafe_allow_html=True,
    )

    fase_1, fase_2, fase_3 = st.columns(3)

    fase_1.info(
        """
        **Fase 1 — Compatibilidad**

        Crear un grupo OCI por cada rol ERP actual.

        Permite una migración progresiva y reversible.
        """
    )

    fase_2.info(
        """
        **Fase 2 — Normalización**

        Definir familias y capacidades después de describir
        correctamente las funciones.
        """
    )

    fase_3.info(
        """
        **Fase 3 — Simplificación**

        Retirar roles heredados sólo después de demostrar
        equivalencia funcional.
        """
    )

    st.subheader(
        "Atributos Custom User propuestos"
    )

    atributos_personalizados = (
        st.session_state.mapeo_atributos[
            st.session_state.mapeo_atributos[
                "esquema"
            ] == "Custom User"
        ]
    )

    st.dataframe(
        atributos_personalizados[
            [
                "origen_erp",
                "destino_oci",
                "tipo_oci",
                "claim_oidc",
                "estado",
                "observacion",
            ]
        ],
        hide_index=True,
        use_container_width=True,
    )

    columna_json_1, columna_json_2 = st.columns(2)

    json_esquema = json.dumps(
        crear_json_esquema_personalizado(
            st.session_state.mapeo_atributos
        ),
        ensure_ascii=False,
        indent=2,
    )

    json_claims = json.dumps(
        crear_json_claims(
            st.session_state.mapeo_atributos
        ),
        ensure_ascii=False,
        indent=2,
    )

    with columna_json_1:
        st.markdown(
            "#### Borrador de esquema SCIM"
        )

        st.code(
            json_esquema,
            language="json",
        )

        st.download_button(
            "Descargar esquema SCIM",
            data=json_esquema.encode("utf-8"),
            file_name="oci_custom_schema_patch.json",
            mime="application/json",
        )

    with columna_json_2:
        st.markdown(
            "#### Borrador de claims"
        )

        st.code(
            json_claims,
            language="json",
        )

        st.download_button(
            "Descargar claims",
            data=json_claims.encode("utf-8"),
            file_name="oci_custom_claims.json",
            mime="application/json",
        )

    st.warning(
        "Estos JSON son documentación de diseño. No se aplican "
        "automáticamente en OCI."
    )


# ============================================================
# SIMULADOR DE TOKEN
# ============================================================

with tab_token:
    st.subheader(
        "Simulación de la identidad recibida por el ERP"
    )

    ids_usuarios = sorted(
        usuarios_roles[
            "ID_DUSUARIOS_FK"
        ]
        .dropna()
        .astype(int)
        .unique()
    )

    usuario_seleccionado = st.selectbox(
        "Selecciona un ID de usuario ERP",
        ids_usuarios,
    )

    ids_roles_usuario = (
        usuarios_roles[
            usuarios_roles["ID_DUSUARIOS_FK"]
            == usuario_seleccionado
        ]["ID_DROLES_FK"]
        .dropna()
        .astype(int)
        .unique()
        .tolist()
    )

    roles_usuario = (
        st.session_state.mapeo_roles[
            st.session_state.mapeo_roles[
                "ID_DROLES"
            ]
            .astype(int)
            .isin(ids_roles_usuario)
        ]
    )

    ids_funciones_usuario: set[int] = set()

    for id_rol in ids_roles_usuario:
        ids_funciones_usuario |= (
            funciones_por_rol.get(
                id_rol,
                set(),
            )
        )

    funciones_usuario_clasificadas = (
        st.session_state.mapeo_funciones[
            st.session_state.mapeo_funciones[
                "ID_DFUNCION"
            ].isin(ids_funciones_usuario)
            & st.session_state.mapeo_funciones[
                "capacidad_objetivo"
            ].ne("SIN_CLASIFICAR")
            & st.session_state.mapeo_funciones[
                "capacidad_objetivo"
            ].ne("NO_MIGRAR_A_OCI")
        ]
    )

    capacidades_usuario = sorted(
        funciones_usuario_clasificadas[
            "capacidad_objetivo"
        ]
        .dropna()
        .unique()
        .tolist()
    )

    token_simulado = {
        "iss": "https://<identity-domain-url>/",
        "sub": "<oci-user-guid>",
        "aud": "<erp-client-id>",
        "exp": 1893456000,
        "iat": 1893452400,
        "auth_time": 1893452300,
        "amr": [
            "pwd",
            "mfa",
        ],
        "preferred_username":
            "<pendiente-maestro-usuarios>",
        "erp_user_id":
            f"ERP:{usuario_seleccionado}",
        "groups": (
            roles_usuario[
                "grupo_oci_propuesto"
            ]
            .dropna()
            .tolist()
        ),
        "erp_families": sorted(
            roles_usuario[
                "familia_propuesta"
            ]
            .dropna()
            .unique()
            .tolist()
        ),
        "erp_capabilities":
            capacidades_usuario,
        "erp_tipo_usuario": "<pendiente>",
        "erp_nivel": "<pendiente>",
        "erp_codigo_mediador": "<pendiente>",
        "erp_delegacion": "<pendiente>",
        "erp_empresa": "<pendiente>",
    }

    izquierda, derecha = st.columns(2)

    with izquierda:
        st.code(
            json.dumps(
                token_simulado,
                ensure_ascii=False,
                indent=2,
            ),
            language="json",
        )

    with derecha:
        st.metric(
            "Roles o grupos",
            len(token_simulado["groups"]),
        )

        st.metric(
            "Funciones ERP efectivas",
            len(ids_funciones_usuario),
        )

        st.metric(
            "Capacidades clasificadas",
            len(capacidades_usuario),
        )

        st.dataframe(
            roles_usuario[
                [
                    "CODIGROL",
                    "familia_propuesta",
                    "grupo_oci_propuesto",
                    "estado_decision",
                ]
            ],
            hide_index=True,
            use_container_width=True,
        )

    st.info(
        "El ERP debe validar la firma del token, el emisor, "
        "la audiencia, la caducidad, nonce y state antes de "
        "crear la sesión."
    )


# ============================================================
# EXPORTACIÓN
# ============================================================

with tab_exportar:
    st.subheader(
        "Exportar decisiones"
    )

    roles_validados = int(
        st.session_state.mapeo_roles[
            "estado_decision"
        ].eq("Validado").sum()
    )

    funciones_clasificadas = int(
        st.session_state.mapeo_funciones[
            "capacidad_objetivo"
        ].ne("SIN_CLASIFICAR").sum()
    )

    atributos_validados = int(
        st.session_state.mapeo_atributos[
            "estado"
        ].eq("Validado").sum()
    )

    columnas = st.columns(3)

    columnas[0].metric(
        "Roles validados",
        (
            f"{roles_validados}/"
            f"{len(st.session_state.mapeo_roles)}"
        ),
    )

    columnas[1].metric(
        "Funciones clasificadas",
        (
            f"{funciones_clasificadas}/"
            f"{len(st.session_state.mapeo_funciones)}"
        ),
    )

    columnas[2].metric(
        "Atributos validados",
        (
            f"{atributos_validados}/"
            f"{len(st.session_state.mapeo_atributos)}"
        ),
    )

    paquete = crear_paquete_exportacion(
        st.session_state.mapeo_roles,
        st.session_state.mapeo_funciones,
        st.session_state.mapeo_atributos,
        informe_calidad,
    )

    st.download_button(
        "Descargar todos los mapeos",
        data=paquete,
        file_name="mapeos_erp_oci_iam.zip",
        mime="application/zip",
        use_container_width=True,
        type="primary",
    )

    columna_1, columna_2, columna_3 = st.columns(3)

    columna_1.download_button(
        "Descargar roles",
        data=dataframe_csv(
            st.session_state.mapeo_roles
        ),
        file_name="mapeo_roles_oci.csv",
        mime="text/csv",
    )

    columna_2.download_button(
        "Descargar funciones",
        data=dataframe_csv(
            st.session_state.mapeo_funciones
        ),
        file_name="mapeo_funciones_capacidades.csv",
        mime="text/csv",
    )

    columna_3.download_button(
        "Descargar atributos",
        data=dataframe_csv(
            st.session_state.mapeo_atributos
        ),
        file_name="mapeo_atributos_scim.csv",
        mime="text/csv",
    )

    st.markdown(
        """
        <div class="aviso aviso-amarillo">
            <b>Antes del piloto:</b> incorporar el maestro completo
            de usuarios, describir las funciones, revisar permisos
            críticos, comprobar segregación de funciones y validar
            varios usuarios representativos antes y después.
        </div>
        """,
        unsafe_allow_html=True,
    )
