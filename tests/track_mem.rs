use std::io::{BufRead, BufReader};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::process::{Child, Command, Stdio};

const IMAGES_DIR: &str = "test/track_mem_images";
const PARENT_DIR: &str = "parent";
const CHILD_DIR: &str = "child";

struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn mem_dirty_track_unavailable_reason(criu_bin_path: &str) -> Option<String> {
    let output = Command::new(criu_bin_path)
        .args(["check", "--feature", "mem_dirty_track"])
        .output()
        .unwrap_or_else(|e| panic!("Running '{} check' failed ({:#?})", criu_bin_path, e));
    if output.status.success() {
        return None;
    }
    Some(format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

fn start_loop_mem() -> (KillOnDrop, u64) {
    let mut loop_mem = KillOnDrop(
        Command::new("test/loop_mem")
            .stdout(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("Starting test/loop_mem failed ({:#?})", e)),
    );

    let mut line = String::new();
    BufReader::new(loop_mem.0.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let region_size: u64 = line
        .trim()
        .parse()
        .unwrap_or_else(|e| panic!("Unexpected output from test/loop_mem: {:?} ({})", line, e));

    (loop_mem, region_size)
}

fn pages_size(images_dir: &Path) -> u64 {
    std::fs::read_dir(images_dir)
        .unwrap()
        .map(|entry| entry.unwrap())
        .filter(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            name.starts_with("pages-") && name.ends_with(".img")
        })
        .map(|entry| entry.metadata().unwrap().len())
        .sum()
}

fn dump_with_track_mem(
    criu_bin_path: &str,
    pid: i32,
    images_dir: &Path,
    parent_img: Option<&str>,
    leave_running: bool,
) {
    let directory = std::fs::File::open(images_dir).unwrap();
    let mut criu = rust_criu::Criu::new_with_criu_path(criu_bin_path.to_string()).unwrap();
    criu.set_pid(pid);
    criu.set_images_dir_fd(directory.as_raw_fd());
    criu.set_log_file("dump.log".to_string());
    criu.set_log_level(4);
    criu.set_leave_running(leave_running);
    criu.set_track_mem(true);
    if let Some(parent_img) = parent_img {
        criu.set_parent_img(parent_img.to_string());
    }

    if let Err(e) = criu.dump() {
        panic!(
            "Dumping process into {} failed with {:#?}",
            images_dir.display(),
            e
        );
    }
}

fn track_mem_test(criu_bin_path: &str) {
    if let Some(reason) = mem_dirty_track_unavailable_reason(criu_bin_path) {
        println!(
            "Running track_mem test: skip (mem_dirty_track is not available: {})",
            reason.trim()
        );
        return;
    }

    println!("Running track_mem test");

    let (loop_mem, region_size) = start_loop_mem();
    let pid = loop_mem.0.id() as i32;

    let images_dir = Path::new(IMAGES_DIR);
    let parent_dir = images_dir.join(PARENT_DIR);
    let child_dir = images_dir.join(CHILD_DIR);
    for dir in [&parent_dir, &child_dir] {
        if let Err(e) = std::fs::create_dir_all(dir) {
            panic!(
                "Creating image directory '{}' failed with {:#?}",
                dir.display(),
                e
            );
        }
    }

    println!("Dumping PID {} into {}", pid, parent_dir.display());
    dump_with_track_mem(criu_bin_path, pid, &parent_dir, None, true);
    let parent_pages = pages_size(&parent_dir);
    assert!(
        parent_pages >= region_size,
        "First dump wrote {} bytes of pages, less than the {} byte filled region",
        parent_pages,
        region_size
    );

    // CRIU resolves parent_img relative to the images directory of the dump,
    // so the parent dump is referenced from the child dump directory.
    let parent_img = format!("../{}", PARENT_DIR);
    println!(
        "Dumping PID {} into {} with parent {}",
        pid,
        child_dir.display(),
        parent_img
    );
    dump_with_track_mem(criu_bin_path, pid, &child_dir, Some(&parent_img), false);
    let child_pages = pages_size(&child_dir);
    println!(
        "pages size: parent={} bytes, child={} bytes, filled region={} bytes",
        parent_pages, child_pages, region_size
    );
    assert!(
        child_pages < region_size,
        "Dump with parent_img and track_mem wrote {} bytes of pages, so the unchanged {} byte region was not skipped",
        child_pages,
        region_size
    );

    println!("Cleaning up");
    if let Err(e) = std::fs::remove_dir_all(images_dir) {
        panic!(
            "Removing image directory '{}' failed with {:#?}",
            IMAGES_DIR, e
        );
    }
}

/// Checks that a dump with parent_img and track_mem skips memory that has not
/// changed since the parent dump.
///
/// test/loop_mem fills a region once and never frees or touches it again, so a dump
/// that does not skip unchanged pages always writes at least the region size.
#[test]
fn dump_with_parent_img_and_track_mem_skips_unchanged_pages() {
    let criu_bin_path =
        std::env::var("CRIU_BINARY").expect("CRIU_BINARY must be set to run integration tests");
    track_mem_test(&criu_bin_path);
}
