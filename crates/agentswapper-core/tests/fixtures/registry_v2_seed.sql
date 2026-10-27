INSERT INTO event_log(payload) VALUES('{"type":"registered","profile":{"id":"cafe0000-0000-4000-8000-000000000001","alias":"legacy","harness":"claude","enabled":true}}');
INSERT INTO profiles(id,alias,harness,enabled) VALUES('cafe0000-0000-4000-8000-000000000001','legacy','claude',1);
INSERT INTO event_log(payload) VALUES('{"type":"run_planned","id":"cafe0000-0000-4000-8000-000000000002","profile":"cafe0000-0000-4000-8000-000000000001","kind":"run"}');
INSERT INTO runs(id,profile,kind,started_at) VALUES('cafe0000-0000-4000-8000-000000000002','cafe0000-0000-4000-8000-000000000001','run',(SELECT recorded_at FROM event_log WHERE sequence=2));
