ALTER TABLE ret_archivo_legal
  ADD COLUMN IF NOT EXISTS credencial_guia VARCHAR(255) NULL AFTER protocolo_higiene,
  ADD COLUMN IF NOT EXISTS carta_protesta VARCHAR(255) NULL AFTER credencial_guia;
