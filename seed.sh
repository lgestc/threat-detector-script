cd ~/projects/fakebeat

echo "creating threats"
cargo run -- templates/threat.json -i logs-ti_test -c 3000

echo "creating events"
cargo run -- templates/events.json -i filebeat-url -c 100000

cd ~/projects/threats