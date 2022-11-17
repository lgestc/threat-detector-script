cd ~/projects/fakebeat

echo "creating threats"
cargo run -- templates/threat_url.json -i logs-ti_test_url -c 3000

cargo run -- templates/threat_file.json -i logs-ti_test_file -c 3000

echo "creating events"
cargo run -- templates/event_url.json -i filebeat-url -c 100000

cargo run -- templates/event_file.json -i filebeat-file -c 100000

cd ~/projects/threats