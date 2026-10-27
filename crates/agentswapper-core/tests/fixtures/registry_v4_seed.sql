-- Frozen schema-4 shapes: successful gents client, rebound agent, pending native child.
INSERT INTO event_log(payload,recorded_at) VALUES
('{"type":"registered","profile":{"id":"cafe0000-0000-4000-8000-000000000001","alias":"relay","harness":"gents","enabled":true,"gents":{"address":"127.0.0.1:9191","agent":"worker"}}}', '2026-01-01T00:00:00.000Z'),
('{"type":"run_planned","id":"cafe0000-0000-4000-8000-000000000002","profile":"cafe0000-0000-4000-8000-000000000001","kind":"run","requires_spawn_observation":true}', '2026-01-01T00:00:01.000Z'),
('{"type":"run_spawned","id":"cafe0000-0000-4000-8000-000000000002","pid":42}', '2026-01-01T00:00:02.000Z'),
('{"type":"run_finished","id":"cafe0000-0000-4000-8000-000000000002","exit_code":0,"outcome":"external_client_exited"}', '2026-01-01T00:00:03.000Z'),
('{"type":"rebound","id":"cafe0000-0000-4000-8000-000000000001","binding":{"address":"127.0.0.1:9191","agent":"other_worker"}}', '2026-01-01T00:00:04.000Z'),
('{"type":"registered","profile":{"id":"cafe0000-0000-4000-8000-000000000003","alias":"native","harness":"codex","enabled":true}}', '2026-01-01T00:00:05.000Z'),
('{"type":"run_planned","id":"cafe0000-0000-4000-8000-000000000004","profile":"cafe0000-0000-4000-8000-000000000003","kind":"run","requires_spawn_observation":true}', '2026-01-01T00:00:06.000Z'),
('{"type":"run_spawned","id":"cafe0000-0000-4000-8000-000000000004","pid":43}', '2026-01-01T00:00:07.000Z');
INSERT INTO profiles(id,alias,harness,enabled,gents) VALUES
('cafe0000-0000-4000-8000-000000000001','relay','gents',1,'{"address":"127.0.0.1:9191","agent":"other_worker"}'),
('cafe0000-0000-4000-8000-000000000003','native','codex',1,NULL);
INSERT INTO runs(id,profile,kind,exit_code,outcome,started_at,observed_pid,spawned_at,requires_spawn_observation) VALUES
('cafe0000-0000-4000-8000-000000000002','cafe0000-0000-4000-8000-000000000001','run',0,'external_client_exited','2026-01-01T00:00:01.000Z',42,'2026-01-01T00:00:02.000Z',1),
('cafe0000-0000-4000-8000-000000000004','cafe0000-0000-4000-8000-000000000003','run',NULL,NULL,'2026-01-01T00:00:06.000Z',43,'2026-01-01T00:00:07.000Z',1);
