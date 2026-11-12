printf '%s\n%s\n' "$FIXTURE_PASSWORD" "$FIXTURE_PASSWORD" | smbpasswd -a -s fixture >/dev/null
exec smbd --foreground --no-process-group --debug-stdout
