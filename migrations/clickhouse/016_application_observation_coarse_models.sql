-- Independent tables keep the old process from modifying the new read model.
CREATE TABLE IF NOT EXISTS application_observation_bucket_facts_v2 AS application_observation_bucket_facts;
CREATE TABLE IF NOT EXISTS application_observation_hour_facts AS application_observation_bucket_facts;
CREATE TABLE IF NOT EXISTS application_observation_day_facts AS application_observation_bucket_facts;
