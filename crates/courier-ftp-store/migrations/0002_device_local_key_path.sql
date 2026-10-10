-- courier-ftp client schema v2 (T31): a site's local SSH key file path is
-- device-local (paths differ per machine), like its default local directory.
ALTER TABLE device_local ADD COLUMN key_path_override TEXT;
