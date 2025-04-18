use anyhow::{Result, bail};
use std::{env, fs::File};

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    pub port: u16,
}

impl AppConfig {
    pub fn load() -> Result<Self> {
        let ret = match (
            File::open("./app.yaml"),
            File::open("./etc/config/app.yaml"),
            env::var("APP_CONFIG"),
        ) {
            (Ok(reader), _, _) => serde_yaml::from_reader(reader),
            (_, Ok(reader), _) => serde_yaml::from_reader(reader),
            (_, _, Ok(reader)) => {
                let file = File::open(reader)?;
                serde_yaml::from_reader(file)
            }
            _ => bail!("Config file not found"),
        };
        Ok(ret?)
    }
}
