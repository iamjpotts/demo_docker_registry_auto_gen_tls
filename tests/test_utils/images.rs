
// Docker-in-Docker
pub mod dind {
    pub const IMAGE: &str = "docker";
    pub const TAG: &str = "20.10-dind";
    pub const PORT: u16 = 2376;
}

pub mod nginx {
    pub const IMAGE: &str = "nginx";
    pub const TAG: &str = "1.20";
}

pub mod registry {
    pub const IMAGE: &str = "registry";
    pub const TAG: &str = "2.8";
}