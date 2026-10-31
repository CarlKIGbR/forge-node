-- forge-node N1 Bootstrap (idempotent, vor/nach Migration 0001 ausfuehrbar): nur die Rolle forge_nodehub; das Passwort setzt der Owner in N4 aus einer Secret-Datei (nie in argv/Env).
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'forge_nodehub') THEN
    CREATE ROLE forge_nodehub LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE;
  END IF;
END $$;
