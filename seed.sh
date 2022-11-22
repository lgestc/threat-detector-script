cd ~/projects/fakebeat

cargo run -- \
    templates/threat_url.json -i logs-ti_test_url -c 10000 \
    templates/threat_file.json -i logs-ti_test_file -c 10000 \
    templates/event_url.json -i filebeat-url -c 50000 \
    templates/event_file.json -i filebeat-file -c 50000

cd ~/projects/threats