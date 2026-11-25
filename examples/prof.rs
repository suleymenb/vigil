//! Micro-profiler for sysinfo collectors: `cargo run --release --example prof`
use std::time::Instant;
use sysinfo::*;
fn t<F: FnMut()>(name: &str, mut f: F) { f(); let s = Instant::now(); for _ in 0..10 { f(); } println!("{name:<28} {:>8.2?}", s.elapsed()/10); }
fn main() {
    let mut sys = System::new_all();
    let mut nets = Networks::new_with_refreshed_list();
    let mut disks = Disks::new_with_refreshed_list();
    let mut comps = Components::new_with_refreshed_list();
    t("cpu", || sys.refresh_cpu_all());
    t("memory", || sys.refresh_memory());
    let base = ProcessRefreshKind::nothing();
    t("procs nothing", || { sys.refresh_processes_specifics(ProcessesToUpdate::All, true, base); });
    t("procs cpu", || { sys.refresh_processes_specifics(ProcessesToUpdate::All, true, base.with_cpu()); });
    t("procs cpu+mem", || { sys.refresh_processes_specifics(ProcessesToUpdate::All, true, base.with_cpu().with_memory()); });
    t("procs cpu+mem+disk", || { sys.refresh_processes_specifics(ProcessesToUpdate::All, true, base.with_cpu().with_memory().with_disk_usage()); });
    t("procs +user/cmd/exe(once)", || { sys.refresh_processes_specifics(ProcessesToUpdate::All, true, base.with_cpu().with_memory().with_disk_usage().with_user(UpdateKind::OnlyIfNotSet).with_cmd(UpdateKind::OnlyIfNotSet).with_exe(UpdateKind::OnlyIfNotSet)); });
    t("networks", || nets.refresh(true));
    t("disks", || disks.refresh(true));
    t("components", || comps.refresh(true));
    t("disks storage-only", || disks.refresh_specifics(true, DiskRefreshKind::nothing().with_storage()));
    let mut list = comps.list_mut().iter_mut().collect::<Vec<_>>();
    if let Some(c) = list.first_mut() { let l = c.label().to_string(); t(&format!("1 component ({l})"), || c.refresh()); }
}
