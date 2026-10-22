const renewalCondition = (alias = "d") => `(
  COALESCE(${alias}.renovar, 0) = 1
  OR (${alias}.fecha_registro IS NOT NULL
    AND DATEDIFF(CURRENT_DATE(), DATE(${alias}.fecha_registro)) > 1095)
)`;

const approvedCondition = (alias = "d") => `(
  NOT ${renewalCondition(alias)}
  AND COALESCE(${alias}.concluido, 0) = 1
  AND COALESCE(${alias}.aprobado, 0) = 1
  AND COALESCE(${alias}.giro, 0) <> 0
  AND COALESCE(${alias}.municipio, 0) <> 0
)`;

const concludedCondition = (alias = "d") => `(
  NOT ${renewalCondition(alias)}
  AND COALESCE(${alias}.concluido, 0) = 1
  AND COALESCE(${alias}.aprobado, 0) = 0
)`;

const approvedRegistryCondition = (alias = "d") => `(
  ${approvedCondition(alias)}
  AND EXISTS (SELECT 1 FROM vw_usr_datos v
    WHERE v.clave = ${alias}.clave AND v.visible = 1 AND v.concluido = 1
      AND v.aprobado = 1 AND v.giro <> 0 AND v.municipio <> 0)
)`;

const pendingCondition = (alias = "d") => `(
  NOT ${renewalCondition(alias)}
  AND NOT ${approvedRegistryCondition(alias)}
  AND NOT ${concludedCondition(alias)}
)`;

const statusCase = (alias = "d") => `CASE
  WHEN ${renewalCondition(alias)} THEN 'Renovación'
  WHEN ${approvedRegistryCondition(alias)} THEN 'Aprobado'
  WHEN ${concludedCondition(alias)} THEN 'Concluido'
  ELSE 'Pendiente'
END`;

module.exports = {
  renewalCondition,
  approvedCondition,
  approvedRegistryCondition,
  concludedCondition,
  pendingCondition,
  statusCase,
};
