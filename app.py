from __future__ import annotations

import io
import json
import zipfile

import pandas as pd
import plotly.express as px
import streamlit as st

from analysis_core import (
    Inventory,
    build_capability_mapping,
    build_role_mapping,
    compare_roles,
    duplicate_privilege_definitions,
    filter_snapshot,
    load_consolidated,
    load_legacy,
    privilege_sets,
    role_summary,
    user_redundancy,
)


st.set_page_config(
    page_title="ERP → OCI | Analizador de roles",
    page_icon="🔐",
    layout="wide",
)

st.markdown(
    """
<style>
div[data-testid="stMetric"] {background:#f6f8fb;border:1px solid #e5e9f0;padding:14px;border-radius:12px}
.small-note {color:#536273;font-size:.92rem}
</style>
""",
    unsafe_allow_html=True,
)


@st.cache_data(max_entries=2, show_spinner=False)
def cached_consolidated(raw: bytes, name: str) -> Inventory:
    return load_consolidated(raw, name)


@st.cache_data(max_entries=2, show_spinner=False)
def cached_legacy(
    user_roles_raw: bytes,
    role_functions_raw: bytes,
    roles_raw: bytes,
    functions_raw: bytes | None,
) -> Inventory:
    return load_legacy(user_roles_raw, role_functions_raw, roles_raw, functions_raw)


@st.cache_data(max_entries=6, show_spinner=False)
def cached_comparisons(
    inventory: Inventory, threshold: float, leaf_only: bool
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    return compare_roles(inventory, threshold, leaf_only)


@st.cache_data(max_entries=4, show_spinner=False)
def cached_user_redundancy(
    inventory: Inventory, leaf_only: bool
) -> tuple[pd.DataFrame, pd.DataFrame]:
    return user_redundancy(inventory, leaf_only)


def show_frame(frame: pd.DataFrame, empty_text: str, height: int = 350) -> None:
    if frame.empty:
        st.info(empty_text)
    else:
        st.dataframe(frame, use_container_width=True, hide_index=True, height=height)


def make_export_zip(
    inventory: Inventory,
    role_candidates: pd.DataFrame,
    identical: pd.DataFrame,
    similar: pd.DataFrame,
    subsets: pd.DataFrame,
    covered_roles: pd.DataFrame,
    repeated_grants: pd.DataFrame,
    role_mapping: pd.DataFrame,
    capability_mapping: pd.DataFrame,
) -> bytes:
    valid_role_privileges = inventory.role_privileges[
        inventory.role_privileges["ID_PRIVILEGIO_REFERENCIADO"]
        .astype(str)
        .str.strip()
        .ne("")
    ]
    summary = {
        "fuente": inventory.source_name,
        "usuarios": int(inventory.user_roles["ID_USUARIO_ERP"].nunique()),
        "roles": int(inventory.role_catalog["ID_ROL_ASIGNADO"].nunique()),
        "privilegios": int(
            inventory.privilege_catalog["ID_PRIVILEGIO_REFERENCIADO"].nunique()
        ),
        "asignaciones_usuario_rol": int(
            len(
                inventory.user_roles[
                    ["ID_USUARIO_ERP", "ID_ROL_ASIGNADO"]
                ].drop_duplicates()
            )
        ),
        "relaciones_rol_privilegio": int(
            len(
                valid_role_privileges[
                    ["ID_ROL_ASIGNADO", "ID_PRIVILEGIO_REFERENCIADO"]
                ].drop_duplicates()
            )
        ),
        "avisos_integridad": int(len(inventory.anomalies)),
        "nota": (
            "Los resultados son candidatos de revisión. No autorizan fusiones ni bajas "
            "automáticas y no configuran OCI."
        ),
    }
    readme = """# Exportación de análisis ERP → OCI

Este ZIP contiene propuestas para revisión, no órdenes de cambio.

Orden recomendado:
1. Corregir incidencias de integridad.
2. Confirmar roles sin usuarios o sin privilegios.
3. Validar con negocio los roles idénticos, similares y subconjuntos.
4. Revisar redundancias por usuario.
5. Aprobar el mapa 1:1 inicial de roles a grupos OCI.
6. Mantener los privilegios concretos en el ERP; agruparlos en capacidades solo en una fase posterior.

Un privilegio concedido por varios roles no es necesariamente un error. Un nombre de prueba
o un rol con pocos usuarios tampoco demuestra que esté obsoleto. Se necesitan owners,
estado del usuario, trazas de uso y aprobación de negocio.
"""
    files = {
        "resumen_inventario.json": json.dumps(summary, ensure_ascii=False, indent=2),
        "roles_candidatos_revision.csv": role_candidates.to_csv(index=False),
        "roles_identicos.csv": identical.to_csv(index=False),
        "roles_similares.csv": similar.to_csv(index=False),
        "roles_subconjunto.csv": subsets.to_csv(index=False),
        "usuarios_roles_redundantes.csv": covered_roles.to_csv(index=False),
        "usuarios_privilegios_repetidos.csv": repeated_grants.to_csv(index=False),
        "mapeo_roles_oci.csv": role_mapping.to_csv(index=False),
        "mapeo_privilegios_capacidades.csv": capability_mapping.to_csv(index=False),
        "LEEME.md": readme,
    }
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content.encode("utf-8-sig"))
    return buffer.getvalue()


st.title("Analizador ERP → OCI IAM")
st.caption(
    "Inventario, limpieza guiada y alternativas de mapeo. La app no escribe en el ERP ni en OCI."
)

with st.sidebar:
    st.header("1. Cargar inventario")
    mode = st.radio(
        "Formato de entrada",
        [
            "CSV consolidado de usuarios, roles y privilegios",
            "Tres CSV originales",
        ],
    )
    st.warning(
        "Privacidad: si publicas la app en Streamlit Community Cloud, los archivos se "
        "procesarán en ese servidor. Para datos reales usa alojamiento privado/interno "
        "o archivos anonimizados."
    )

inventory: Inventory | None = None
if mode == "CSV consolidado de usuarios, roles y privilegios":
    with st.sidebar:
        consolidated_file = st.file_uploader(
            "Sube el inventario consolidado",
            type=["csv"],
            help=(
                "Espera las columnas ENTORNO, FECHA_EXTRACCION, ID_USUARIO_ERP, "
                "CODIGO_ROL, CODIGO_PRIVILEGIO, DESCRIPCION_PRIVILEGIO, etc."
            ),
        )
    if consolidated_file is not None:
        try:
            with st.spinner("Leyendo y normalizando el inventario…"):
                inventory = cached_consolidated(
                    consolidated_file.getvalue(), consolidated_file.name
                )
        except Exception as exc:
            st.error(f"No se pudo interpretar el CSV consolidado: {exc}")
            st.stop()
else:
    with st.sidebar:
        droluser_file = st.file_uploader("DROLUSER", type=["csv"])
        drolfunc_file = st.file_uploader("DROLFUNC", type=["csv"])
        droles_file = st.file_uploader("DROLES", type=["csv"])
        dfuncion_file = st.file_uploader(
            "DFUNCION (opcional, recomendado)",
            type=["csv"],
            help="Añade código y descripción de los privilegios.",
        )
    if droluser_file and drolfunc_file and droles_file:
        try:
            with st.spinner("Uniendo los catálogos…"):
                inventory = cached_legacy(
                    droluser_file.getvalue(),
                    drolfunc_file.getvalue(),
                    droles_file.getvalue(),
                    dfuncion_file.getvalue() if dfuncion_file else None,
                )
        except Exception as exc:
            st.error(f"No se pudieron interpretar los CSV: {exc}")
            st.stop()

if inventory is None:
    st.info(
        "Sube el CSV consolidado de PRO, o cambia al formato de tres CSV. "
        "Los archivos solo se leen cuando los seleccionas."
    )
    st.markdown(
        """
### Qué podrá detectar

- Incidencias de integridad y roles sin usuarios o sin privilegios.
- Roles con conjuntos idénticos, muy parecidos o contenidos en otros.
- Usuarios con roles potencialmente cubiertos por otros roles.
- Privilegios que llegan al mismo usuario a través de varios roles.
- Un mapa inicial de cada rol ERP a un grupo OCI y una propuesta posterior por capacidades.

Los resultados son **candidatos a revisión**, no cambios automáticos.
"""
    )
    st.stop()

environments = sorted(
    value
    for value in inventory.user_roles.get("ENTORNO", pd.Series(dtype=str)).unique()
    if value
)
dates = sorted(
    value
    for value in inventory.user_roles.get("FECHA_EXTRACCION", pd.Series(dtype=str)).unique()
    if value
)
with st.sidebar:
    st.header("2. Seleccionar foto")
    selected_environment = (
        st.selectbox("Entorno", environments) if environments else ""
    )
    selected_date = st.selectbox("Fecha de extracción", dates) if dates else ""
    leaf_only = st.toggle(
        "Comparar solo operaciones finales (IT)",
        value=True,
        help="Evita que las raíces y grupos estructurales inflen la similitud.",
    )
    similarity_threshold = st.slider(
        "Umbral de similitud", 0.50, 1.00, 0.85, 0.01
    )
    low_use_limit = st.number_input(
        "Pocos usuarios: hasta", min_value=0, max_value=100, value=1
    )

snapshot = filter_snapshot(inventory, selected_environment, selected_date)
if len(dates) <= 1:
    st.info(
        "El archivo contiene una sola fecha de extracción: es una foto consolidada. "
        "Para analizar altas, bajas y evolución hacen falta varias extracciones."
    )

summary = role_summary(snapshot)
identical, similar, subsets = cached_comparisons(
    snapshot, similarity_threshold, leaf_only
)
covered_roles, repeated_grants = cached_user_redundancy(snapshot, leaf_only)
duplicate_definitions = duplicate_privilege_definitions(snapshot)
role_mapping_default = build_role_mapping(snapshot, identical, int(low_use_limit))
capability_mapping_default = build_capability_mapping(snapshot)

user_role_pairs = snapshot.user_roles[
    ["ID_USUARIO_ERP", "ID_ROL_ASIGNADO"]
].drop_duplicates()
role_privilege_pairs = snapshot.role_privileges[
    snapshot.role_privileges["ID_PRIVILEGIO_REFERENCIADO"].astype(str).str.strip().ne("")
][["ID_ROL_ASIGNADO", "ID_PRIVILEGIO_REFERENCIADO"]].drop_duplicates()
users = int(snapshot.user_roles["ID_USUARIO_ERP"].nunique())
roles = int(snapshot.role_catalog["ID_ROL_ASIGNADO"].nunique())
privileges = int(
    snapshot.privilege_catalog.loc[
        snapshot.privilege_catalog["ID_PRIVILEGIO_REFERENCIADO"]
        .astype(str)
        .str.strip()
        .ne(""),
        "ID_PRIVILEGIO_REFERENCIADO",
    ].nunique()
)

tab_overview, tab_cleanup, tab_roles, tab_users, tab_oci, tab_export = st.tabs(
    [
        "Radiografía",
        "Limpieza ERP",
        "Roles repetidos",
        "Usuarios y redundancias",
        "Mapa OCI",
        "Exportar",
    ]
)

with tab_overview:
    cols = st.columns(5)
    cols[0].metric("Usuarios", f"{users:,}".replace(",", "."))
    cols[1].metric("Roles", f"{roles:,}".replace(",", "."))
    cols[2].metric("Privilegios", f"{privileges:,}".replace(",", "."))
    cols[3].metric("Usuario ↔ rol", f"{len(user_role_pairs):,}".replace(",", "."))
    cols[4].metric(
        "Rol ↔ privilegio", f"{len(role_privilege_pairs):,}".replace(",", ".")
    )
    st.markdown(
        """
```text
USUARIO ──< DROLUSER >── ROL ──< DROLFUNC >── DFUNCION / PRIVILEGIO
 muchos usuarios por rol       muchos privilegios por rol
```
El acceso efectivo de un usuario se aproxima a la **unión** de los privilegios de sus
roles. Conviene confirmar con IT si existen permisos directos, denegaciones o herencia
fuera de estas tablas.
"""
    )
    left, right = st.columns(2)
    with left:
        top_roles = summary.head(20)
        figure = px.bar(
            top_roles.sort_values("USUARIOS"),
            x="USUARIOS",
            y="CODIGO_ROL",
            orientation="h",
            title="20 roles con más usuarios",
        )
        st.plotly_chart(figure, use_container_width=True)
    with right:
        type_counts = (
            snapshot.role_privileges["TIPO_PRIVILEGIO"]
            .replace("", "SIN CLASIFICAR")
            .value_counts()
            .rename_axis("TIPO")
            .reset_index(name="RELACIONES")
        )
        figure = px.pie(
            type_counts,
            names="TIPO",
            values="RELACIONES",
            hole=0.45,
            title="Relaciones por tipo de privilegio",
        )
        st.plotly_chart(figure, use_container_width=True)
    st.subheader("Inventario por rol")
    show_frame(summary, "No hay roles en la foto seleccionada.", 420)

with tab_cleanup:
    st.subheader("Orden de limpieza recomendado dentro del ERP")
    st.markdown(
        """
1. Corregir referencias rotas y roles inexistentes.
2. Confirmar roles sin usuarios o sin privilegios.
3. Revisar funciones duplicadas reales.
4. Validar roles con privilegios idénticos, similares o contenidos en otros.
5. Revisar redundancias usuario a usuario antes de retirar asignaciones.
6. Aplicar cambios gradualmente, con owner, aprobación, prueba y reversión.
"""
    )
    st.warning(
        "Un rol con pocos usuarios o nombre de prueba no está demostrado como obsoleto. "
        "Para decidirlo faltan estado del usuario, fecha de último uso, owner y trazas."
    )
    st.subheader("Incidencias de integridad")
    show_frame(
        snapshot.anomalies,
        "No se han encontrado incidencias de integridad en esta foto.",
    )
    role_candidates = summary[
        (summary["USUARIOS"] <= int(low_use_limit))
        | (summary["PRIVILEGIOS"] == 0)
        | (summary["AVISOS_INTEGRIDAD"] > 0)
        | summary["NOMBRE_A_REVISAR"]
    ].copy()
    st.subheader("Roles candidatos a revisar")
    show_frame(
        role_candidates,
        "No hay candidatos con los criterios actuales.",
    )
    st.subheader("Definiciones de privilegio realmente duplicadas")
    st.caption(
        "Mismo código y descripción asociados a varios identificadores. No confundir "
        "con un privilegio utilizado por muchos roles."
    )
    show_frame(
        duplicate_definitions,
        "No se han detectado definiciones duplicadas con este criterio.",
    )
    transversal = (
        snapshot.role_privileges[
            snapshot.role_privileges["ID_PRIVILEGIO_REFERENCIADO"]
            .astype(str)
            .str.strip()
            .ne("")
        ].groupby(
            [
                "ID_PRIVILEGIO_REFERENCIADO",
                "CODIGO_PRIVILEGIO",
                "DESCRIPCION_PRIVILEGIO",
            ],
            dropna=False,
        )["ID_ROL_ASIGNADO"]
        .nunique()
        .rename("NUM_ROLES")
        .reset_index()
        .sort_values("NUM_ROLES", ascending=False)
    )
    st.subheader("Privilegios más transversales")
    st.caption("Que aparezcan en varios roles es normal; sirve para localizar alto impacto.")
    show_frame(transversal.head(50), "No hay información de privilegios.")

with tab_roles:
    st.subheader("Roles con el mismo contenido")
    show_frame(
        identical,
        "No hay pares con conjuntos de privilegios idénticos.",
    )
    st.subheader(f"Roles con similitud ≥ {similarity_threshold:.0%}")
    show_frame(
        similar,
        "No hay pares no idénticos que superen el umbral.",
    )
    st.subheader("Roles cuyo contenido está incluido en otro")
    show_frame(
        subsets,
        "No hay relaciones de subconjunto.",
    )
    st.divider()
    st.subheader("Comparador de dos roles")
    role_options = (
        snapshot.role_catalog.sort_values("CODIGO_ROL")
        .assign(
            LABEL=lambda frame: frame["CODIGO_ROL"]
            + " ["
            + frame["ID_ROL_ASIGNADO"].astype(str)
            + "]"
        )
        .drop_duplicates("ID_ROL_ASIGNADO")
    )
    if len(role_options) >= 2:
        option_map = dict(
            zip(role_options["LABEL"], role_options["ID_ROL_ASIGNADO"])
        )
        col_a, col_b = st.columns(2)
        labels = list(option_map)
        label_a = col_a.selectbox("Rol A", labels, index=0)
        label_b = col_b.selectbox("Rol B", labels, index=min(1, len(labels) - 1))
        sets = privilege_sets(snapshot, leaf_only)
        set_a = sets.get(option_map[label_a], set())
        set_b = sets.get(option_map[label_b], set())
        privilege_lookup = (
            snapshot.privilege_catalog.drop_duplicates("ID_PRIVILEGIO_REFERENCIADO")
            .set_index("ID_PRIVILEGIO_REFERENCIADO")[
                ["CODIGO_PRIVILEGIO", "DESCRIPCION_PRIVILEGIO"]
            ]
        )

        def detail(ids: set[str]) -> pd.DataFrame:
            if not ids:
                return pd.DataFrame(columns=["ID_PRIVILEGIO", "CODIGO", "DESCRIPCION"])
            rows = privilege_lookup.reindex(sorted(ids)).reset_index()
            return rows.rename(
                columns={
                    "ID_PRIVILEGIO_REFERENCIADO": "ID_PRIVILEGIO",
                    "CODIGO_PRIVILEGIO": "CODIGO",
                    "DESCRIPCION_PRIVILEGIO": "DESCRIPCION",
                }
            )

        common, only_a, only_b = st.tabs(
            [
                f"Comunes ({len(set_a & set_b)})",
                f"Solo A ({len(set_a - set_b)})",
                f"Solo B ({len(set_b - set_a)})",
            ]
        )
        with common:
            show_frame(detail(set_a & set_b), "No tienen privilegios comunes.")
        with only_a:
            show_frame(detail(set_a - set_b), "A no aporta privilegios exclusivos.")
        with only_b:
            show_frame(detail(set_b - set_a), "B no aporta privilegios exclusivos.")

with tab_users:
    cols = st.columns(3)
    cols[0].metric(
        "Usuarios con rol cubierto",
        (
            covered_roles["ID_USUARIO_ERP"].nunique()
            if not covered_roles.empty
            else 0
        ),
    )
    cols[1].metric(
        "Usuarios con concesión repetida",
        (
            repeated_grants["ID_USUARIO_ERP"].nunique()
            if not repeated_grants.empty
            else 0
        ),
    )
    cols[2].metric(
        "Concesiones extra",
        (
            int(repeated_grants["CONCESIONES_EXTRA"].sum())
            if not repeated_grants.empty
            else 0
        ),
    )
    st.caption(
        "“Cubierto” significa que, para esta foto y este alcance, los privilegios de un "
        "rol también llegan por otro. No demuestra que retirar el rol sea seguro."
    )
    st.subheader("Roles potencialmente redundantes por usuario")
    show_frame(
        covered_roles,
        "No se han detectado roles cubiertos por otros para un mismo usuario.",
        420,
    )
    st.subheader("Privilegios concedidos por varios roles al mismo usuario")
    if repeated_grants.empty:
        st.info("No se han detectado concesiones repetidas.")
    else:
        repeated_by_user = (
            repeated_grants.groupby("ID_USUARIO_ERP")
            .agg(
                PRIVILEGIOS_REPETIDOS=("ID_PRIVILEGIO", "nunique"),
                CONCESIONES_EXTRA=("CONCESIONES_EXTRA", "sum"),
            )
            .reset_index()
            .sort_values("CONCESIONES_EXTRA", ascending=False)
        )
        st.dataframe(
            repeated_by_user.head(100),
            use_container_width=True,
            hide_index=True,
            height=360,
        )
        st.caption(
            "Se muestran los 100 usuarios con más solapamiento. El detalle completo "
            "se incluye en la exportación."
        )
    all_users = sorted(snapshot.user_roles["ID_USUARIO_ERP"].dropna().unique(), key=str)
    if all_users:
        selected_user = st.selectbox("Ver detalle de un usuario", all_users)
        user_assignments = snapshot.user_roles[
            snapshot.user_roles["ID_USUARIO_ERP"] == selected_user
        ][
            [
                "ID_ROL_ASIGNADO",
                "CODIGO_ROL",
                "DESCRIPCION_ROL",
                "FECHA_ASIGNACION_ROL",
            ]
        ].drop_duplicates()
        show_frame(user_assignments, "El usuario no tiene roles.")
        if not covered_roles.empty:
            st.markdown("**Roles cubiertos para este usuario**")
            show_frame(
                covered_roles[covered_roles["ID_USUARIO_ERP"] == selected_user],
                "No se detectan roles cubiertos para este usuario.",
                260,
            )
        if not repeated_grants.empty:
            st.markdown("**Concesiones repetidas para este usuario**")
            show_frame(
                repeated_grants[repeated_grants["ID_USUARIO_ERP"] == selected_user],
                "No se detectan concesiones repetidas para este usuario.",
                300,
            )

with tab_oci:
    st.subheader("Alternativas de mapeo")
    option = st.radio(
        "Modelo",
        [
            "Híbrido (recomendado)",
            "1 grupo OCI por rol ERP",
            "Grupos OCI por capacidad de negocio",
        ],
        horizontal=True,
    )
    if option == "Híbrido (recomendado)":
        st.success(
            "Fase 1: OCI autentica y entrega grupos equivalentes a los roles ERP. "
            "El ERP conserva DROLFUNC/DFUNCION y decide las operaciones concretas. "
            "Fase 2: solo tras limpiar y aprobar, agrupar privilegios finales en capacidades."
        )
    elif option == "1 grupo OCI por rol ERP":
        st.info(
            "Es el camino más trazable para empezar, aunque reproduce parte de la "
            "complejidad actual. Evita crear un grupo OCI por cada privilegio técnico."
        )
    else:
        st.warning(
            "Es el modelo objetivo más limpio, pero requiere owner, semántica confirmada, "
            "matriz SoD, pruebas y aprobación de negocio. No debe deducirse solo por nombres."
        )
    st.markdown(
        """
```text
OCI Identity Domain
  usuario + MFA + ciclo de vida
           │
           ├── grupos ERP_ROLE_* ──> rol ERP existente
           │                            └── DROLFUNC ──> privilegios concretos
           └── atributos/claims estables: externalId, organización, colectivo...
```
"""
    )
    st.caption(
        "Usa `externalId` como vínculo estable con el identificador ERP. Los atributos "
        "organizativos deben proceder de una fuente maestra, no inferirse del nombre del rol."
    )
    st.subheader("Propuesta editable: rol ERP → grupo OCI")
    role_mapping = st.data_editor(
        role_mapping_default,
        use_container_width=True,
        hide_index=True,
        num_rows="fixed",
        key=f"role_mapping_{inventory.source_name}_{selected_environment}_{selected_date}",
        height=480,
    )
    st.subheader("Propuesta editable: privilegio → capacidad")
    st.caption(
        "Las capacidades se sugieren por palabras; `SIN_CLASIFICAR` exige decisión humana. "
        "El destino inicial es mantener el privilegio concreto en el ERP."
    )
    capability_mapping = st.data_editor(
        capability_mapping_default,
        use_container_width=True,
        hide_index=True,
        num_rows="fixed",
        key=f"capability_mapping_{inventory.source_name}_{selected_environment}_{selected_date}",
        height=480,
    )

with tab_export:
    st.subheader("Descargar resultados")
    st.write(
        "El ZIP contiene tablas de análisis y propuestas editables. No contiene los CSV "
        "originales, credenciales ni instrucciones que cambien el ERP u OCI."
    )
    if "role_mapping" not in locals():
        role_mapping = role_mapping_default
    if "capability_mapping" not in locals():
        capability_mapping = capability_mapping_default
    role_candidates = summary[
        (summary["USUARIOS"] <= int(low_use_limit))
        | (summary["PRIVILEGIOS"] == 0)
        | (summary["AVISOS_INTEGRIDAD"] > 0)
        | summary["NOMBRE_A_REVISAR"]
    ].copy()
    export_bytes = make_export_zip(
        snapshot,
        role_candidates,
        identical,
        similar,
        subsets,
        covered_roles,
        repeated_grants,
        role_mapping,
        capability_mapping,
    )
    st.download_button(
        "Descargar análisis en ZIP",
        data=export_bytes,
        file_name="analisis_erp_oci.zip",
        mime="application/zip",
        type="primary",
    )
