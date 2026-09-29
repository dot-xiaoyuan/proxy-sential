ALTER TABLE application_connection_summaries
 ADD COLUMN IF NOT EXISTS summary_apps Array(String) MATERIALIZED arrayDistinct(arrayMap(o->o.3,arrayFilter(o->o.4='application',events))),
 ADD COLUMN IF NOT EXISTS summary_upload Nullable(UInt64) MATERIALIZED arrayReduce('max',arrayMap(o->o.7,events)),
 ADD COLUMN IF NOT EXISTS summary_download Nullable(UInt64) MATERIALIZED arrayReduce('max',arrayMap(o->o.8,events)),
 ADD COLUMN IF NOT EXISTS summary_terminals Array(Tuple(String,String)) MATERIALIZED arrayDistinct(arrayMap(o->tuple(campus_id,o.2),arrayFilter(o->o.2!='',events))),
 ADD COLUMN IF NOT EXISTS summary_label Tuple(String,String) MATERIALIZED tuple(arraySort(o->tuple(o.1,o.9),arrayFilter(o->o.4='application',events))[-1].5,arraySort(o->tuple(o.1,o.9),arrayFilter(o->o.4='application',events))[-1].6);

ALTER TABLE application_connection_summaries
 MATERIALIZE COLUMN summary_apps,
 MATERIALIZE COLUMN summary_upload,
 MATERIALIZE COLUMN summary_download,
 MATERIALIZE COLUMN summary_terminals,
 MATERIALIZE COLUMN summary_label
 SETTINGS mutations_sync=2;
