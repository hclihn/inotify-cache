package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
  "log"
	"math"
	"path/filepath"
	"reflect"
  "runtime"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
  MaxInotifyEvents = 1024
  AvgInotifyNameLen = 16
  MaxEpollEvents = 32
  InotifyEventBufSize = MaxInotifyEvents*(unix.SizeofInotifyEvent+AvgInotifyNameLen)
  EventsInitCap = 64
)

var (
  eventBufPool = sync.Pool{
    New: func() any {
      return make([]byte, InotifyEventBufSize)
    },
  }

  eventsPool = sync.Pool{
    New: func() any {
      return make([]*InotifyEvent, 0, EventsInitCap)
    },
  }

  // mask bit number to string mapping
 in_mapping = map[int]string {
    0:        "IN_ACCESS", // 0x1
    1:        "IN_MODIFY", // 0x2
    2:        "IN_ATTRIB", // 0x4
    3:   "IN_CLOSE_WRITE", // 0x8
    4: "IN_CLOSE_NOWRITE", // 0x10
    5:          "IN_OPEN", // 0x20
    6:    "IN_MOVED_FROM", // 0x40
    7:      "IN_MOVED_TO", // 0x80
    8:        "IN_CREATE", // 0x100
    9:        "IN_DELETE", // 0x200
    10:   "IN_DELETE_SELF", // 0x400
    11:     "IN_MOVE_SELF", // 0x800, IN_ALL_EVENTS covers up to here
    13:       "IN_UNMOUNT", // 0x2000, in read event only
    14:    "IN_Q_OVERFLOW", // 0x4000, in read event only
    15:       "IN_IGNORED", // 0x8000, in read event only
    24:       "IN_ONLYDIR", // 0x1000000, used with inotify_add_watch() only
    25:   "IN_DONT_FOLLOW", // 0x2000000, used with inotify_add_watch() only
    26:   "IN_EXCL_UNLINK", // 0x4000000, used with inotify_add_watch() only
    28:   "IN_MASK_CREATE", // 0x10000000, used with inotify_add_watch() only
    29:      "IN_MASK_ADD", // 0x20000000, used with inotify_add_watch() only
    30:         "IN_ISDIR", // 0x40000000, in read event only
    31:       "IN_ONESHOT", // 0x80000000, used with inotify_add_watch() only
  }    
)

func InMaskToString(in_mask uint32) string {
  var sb strings.Builder
  // each mask is one bit
  hasName := false
  for i, m := 0, uint32(1); i < 32 && in_mask > 0; i++ {
    if in_mask&m != 0 {
      in_mask &^= m
      name, ok := in_mapping[i]
      if !ok {
        name = fmt.Sprintf("IN_UNKNOWN_%d", i)
      }
      if hasName {
          sb.WriteString("|")
      }
      sb.WriteString(name)
      hasName = true
    }
    m <<= 1
  }
  return sb.String()
}

func IsSubpath(parent, child string) bool {
  if s, err := filepath.Rel(parent, child); err != nil {
    return false
  } else if s == "." { // self
    return true
  } else if strings.HasPrefix(s, "..") { // child outside parent
    return false
  }
  return true
}

// If the pattern doesn't contain the glob pattern, teh scroe is MaxInt (highest).
// Otherwise, the higher the score, the more specific is the glob pattern, roughly.
func globScore(pattern string) int {
  const magicChars = `*?[`
  if !strings.ContainsAny(pattern, magicChars) {
    return math.MaxInt
  }
  return len(pattern)
}

func UpdateInotifyMask(old, new uint32) uint32 {
  if new&unix.IN_MASK_ADD == 0 { // replace mask
    return new
  }
  // update mask
  return old | (new &^ unix.IN_MASK_ADD)
}

func SplitPath(path string) (string, string) {
  dir, file := filepath.Split(path)
  dir = filepath.Clean(dir)
  return dir, file
}

func UpdateFnList(old, new []UpdateFn) []UpdateFn {
  if len(new) == 0 {
    return old
  } else if len(old) == 0 {
    return new
  }
  oldMap := make(map[uintptr]struct{})
  for _, fn := range old {
    oldMap[reflect.ValueOf(fn).Pointer()] = struct{}{}
  }
  toAdd := make([]UpdateFn, 0)
  // update fn list
  for _, fn := range new {
    if fn == nil { // just in case
      continue
    }
    if _, ok := oldMap[reflect.ValueOf(fn).Pointer()]; ok {
      continue
    }
    toAdd = append(toAdd, fn)
  }
  return append(old, toAdd...)
}

func GetFuncName(fn any) string {
  f := runtime.FuncForPC(reflect.ValueOf(fn).Pointer())
  if strings.Contains(f.Name(), ".func") {
    file, line := f.FileLine(f.Entry())
    return fmt.Sprintf("%s(%s:%d)", f.Name(), file, line)
  }
  return f.Name()
}

// Event represents a notification
type InotifyEvent struct {
  Wd uint32 // Watch descriptor
  Mask   uint32 // Mask of events
  Cookie uint32 // Unique cookie associating related events (for rename(2))
  Name   string // File name 
  Path string // Full path
}

func (e *InotifyEvent) String() string {
  return fmt.Sprintf("InotifyEvent{wd: %d, name: %s, path: %s, cookie: %d, mask: %s}", 
    e.Wd, e.Name, e.Path, e.Cookie, InMaskToString(e.Mask))
}

type UpdateFn func(*InotifyEvent)

type fileInfo struct {
  name string // file name
  mask uint32
  update []UpdateFn // Callback to invoke when an event is received
}

func (fi *fileInfo) ToString(indent int) string {
  return fmt.Sprintf("%s%s", strings.Repeat(" ", indent), fi)
}

func (fi *fileInfo) String() string {
  var sb strings.Builder
  fmt.Fprintf(&sb, "fileInfo{name: %s, mask: %s, update functions: [", fi.name, InMaskToString(fi.mask))
  hasName := false
  for _, fn := range fi.update {
    if hasName {
      sb.WriteString(", ")
    }
    sb.WriteString(GetFuncName(fn))
  }
  sb.WriteString("]}")
  return sb.String()
}

type watch struct {
  basePath string
  files []*fileInfo
}

// Watcher represents an inotify instance
type InotifyWatcher struct {
  mu sync.RWMutex
  fd       int               // File descriptor (as returned by the inotify_init() syscall)
  watches  map[uint32]*watch // map of wd (uint32) -> *watch 
  path2wd  map[string]uint32 // map of path (string) -> wd (uint32)
  isDir bool
  dirPath string
}

func (w *InotifyWatcher) String() string {
  return w.ToString(0)
}

func (w *InotifyWatcher) ToString(indent int) string {
  s := strings.Repeat(" ", indent)
  var sb strings.Builder
  fmt.Fprintf(&sb, "InotifyWatcher(fd: %d", w.fd)
  if w.isDir {
    fmt.Fprintf(&sb, ", watch dir: %s):\n", w.dirPath)
  } else {
    sb.WriteString("):\n")
  }
  for wd, watch := range w.watches {
    fmt.Fprintf(&sb, "%s  watch %d: path: %s, files:\n", s, wd, watch.basePath)
    for _, fi := range watch.files {
      fmt.Fprintf(&sb, "%s    %s\n", s, fi)
    }
  }
  return sb.String()
}

// NewWatcher creates and returns a new inotify instance using inotify_init(2)
func NewInotifyWatcher(isDir bool) (*InotifyWatcher, error) {
  // Use IN_NONBLOCK to use edge-triggered epoll
  fd, err := unix.InotifyInit1(unix.IN_CLOEXEC|unix.IN_NONBLOCK)
  if err != nil || fd == -1 {
    return nil, fmt.Errorf("failed inotify_init a watcher: %w", err)
  }
  w := &InotifyWatcher{
    fd:      fd,
    watches: make(map[uint32]*watch),
    path2wd: make(map[string]uint32),
    isDir: isDir,
  }
  return w, nil
}

func (w *InotifyWatcher) Close() error {
  // Upon close(), the underlying object and its resources are freed for reuse by the kernel; 
  // all associated watches are automatically freed.
  w.mu.Lock()
  defer w.mu.Unlock()
  
  w.watches = nil
  w.path2wd = nil
  err := unix.Close(w.fd)
  w.fd = -1
  return err
}

// caller needs to unix.IN_MASK_ADD if the mask is to be updated on an existing watcher
func (w *InotifyWatcher) AddFileWatch(pathName string, mask uint32, fns ...UpdateFn) error {
  if w.isDir {
    return fmt.Errorf("AddFileWatch is not supported for directories")
  } else if len(fns) == 0 {
    return fmt.Errorf("fns cannot be empty")
  } else {
    for i, fn := range fns {
      if fn == nil {
        return fmt.Errorf("fns[%d] cannot be nil", i)
      }
    }
  }
  dir, base := SplitPath(pathName)
  if base == "" {
    base = "*"
  }
  var wi *watch
  w.mu.RLock()
  for _, watch := range w.watches {
    if watch.basePath == dir {
      wi = watch
      break
    }
  }
  w.mu.RUnlock()
  // Filenames are actually attributes of their containing directory, and a single file may be called by multiple names.
  // Need to watch the file's containing directory! Watching the filepath won't trigger!
  if wi != nil {
    w.mu.Lock()
    defer w.mu.Unlock()

    for _, fi := range wi.files {
      if fi.name == base { // update an existing file entry
        fi.mask = UpdateInotifyMask(fi.mask, mask)
        fi.update = UpdateFnList(fi.update, fns)
        return nil
      }
    }
    // new file entry
    wi.files = append(wi.files, &fileInfo{name: base, mask: mask, update: fns})
    return nil
  }
  // new watch
  wd, err := unix.InotifyAddWatch(w.fd, dir, unix.IN_ALL_EVENTS)
  if err != nil {
    return err
  }
  uwd := uint32(wd)
  wi = &watch{basePath: dir, files: make([]*fileInfo, 1)}
  wi.files[0] = &fileInfo{name: base, mask: mask, update: fns}
  w.mu.Lock()
  defer w.mu.Unlock()

  w.watches[uwd] = wi
  w.path2wd[pathName] = uwd
  w.dirPath = ""
  return nil
}

func (w *InotifyWatcher) AddDirWatch(pathName string, mask uint32, fns ...UpdateFn) error {
  if !w.isDir {
    return fmt.Errorf("cannot add dir watch to a file watcher")
  } else if len(fns) == 0 {
    return fmt.Errorf("fns cannot be empty")
  } else {
    for i, fn := range fns {
      if fn == nil {
        return fmt.Errorf("fns[%d] cannot be nil", i)
      }
    }
  }
  if w.dirPath != "" { // modify existing watch
    if pathName != w.dirPath {
      return fmt.Errorf("pathName must be the same as the watcher's dirPath (%s)", w.dirPath)
    }
    // existing one
    w.mu.Lock()
    for _, wi := range w.watches { // update all watchers' mask and update fn
      fi := wi.files[0]
      fi.mask = UpdateInotifyMask(fi.mask, mask)
      fi.update = UpdateFnList(fi.update, fns)
    }
    w.mu.Unlock()
    return nil
  }
  // new one
  w.dirPath = pathName
  err := w.addSubDirs(pathName, mask, fns...)
  return err
}

func (w *InotifyWatcher) addSubDirs(pathName string, mask uint32, fns ...UpdateFn) error {
  err := filepath.WalkDir(pathName, func(p string, d fs.DirEntry, err error) error {
    // p is the full path; while d.Name() is the base name of p
    if err != nil {
      return nil
    }
    if !d.IsDir() {
      return nil
    }
    log.Printf("** Dir Watch %q added\n", p)
    // Add all directories (self and subdir) to watch
    wd, err := unix.InotifyAddWatch(w.fd, p, unix.IN_ALL_EVENTS)
    if err != nil {
      return err
    }
    uwd := uint32(wd)
    wi := &watch{basePath: p, files: make([]*fileInfo, 1)}
    wi.files[0] = &fileInfo{name: "*", mask: mask, update: fns}
    w.mu.Lock()
    defer w.mu.Unlock()

    w.watches[uwd] = wi
    w.path2wd[p] = uwd
    return nil
  })
  return err
}

func (w *InotifyWatcher) RemoveWatch(path string) error {
  w.mu.RLock()
  wd, ok := w.path2wd[path]
  w.mu.RUnlock()
  if !ok {
    return fmt.Errorf("can't remove non-existent inotify watch for: %s", path)
  }
  return w.RemoveWd(wd, path)
}

func (w *InotifyWatcher) RemoveWd(wd uint32, path string) error {
  log.Printf("** Watch %d (%q) removed\n", wd, path)
  success, err := unix.InotifyRmWatch(w.fd, wd)
  if err != nil || success == -1 {
    // returns EBADF if the fd is invalid
    // EINVAL if wd is invalid or fd is not an inotify fd
    // The watcher may be removed by IN_DELETE_SELF
    if !errors.Is(err, unix.EINVAL) || !w.isDir { 
      return fmt.Errorf("failed inotify_rm_watch: %w", err)
    }
  }
  w.mu.Lock()
  defer w.mu.Unlock()
  
  delete(w.watches, wd)
  delete(w.path2wd, path)
  return nil
}

func (w *InotifyWatcher) Read() ([]*InotifyEvent, error) {
  events := eventsPool.Get().([]*InotifyEvent)
  buf := eventBufPool.Get().([]byte)
  // Re-slice to maximum capacity and return it
  // for re-use. This is important to guarantee that
  // all calls to Get() will return a buffer of
  // maximum length.
  defer eventBufPool.Put(buf[:InotifyEventBufSize])
  
  for {
    n, err := unix.Read(w.fd, buf)
    if err != nil {
      // We have IN_NONBLOCK set, read until EAGAIN.
      if errors.Is(err, unix.EAGAIN) { // done reading events
        return events, nil
      }
      return events, err
    }
    if n < unix.SizeofInotifyEvent {
      return events, fmt.Errorf("Short inotify read")
    }

    offset := 0
    for offset+unix.SizeofInotifyEvent <= n {
      event := (*unix.InotifyEvent)(unsafe.Pointer(&buf[offset]))
      namebuf := buf[offset+unix.SizeofInotifyEvent : offset+unix.SizeofInotifyEvent+int(event.Len)]

      offset += unix.SizeofInotifyEvent + int(event.Len)

      if event.Wd == -1 { // wd is -1 for IN_Q_OVERFLOW
        continue
      }
      w.mu.RLock()
      wi, ok := w.watches[uint32(event.Wd)]
      w.mu.RUnlock()
      var basePath string
      if ok { 
        basePath = wi.basePath
      }
      
      name := strings.TrimRight(string(namebuf), "\x00")
      events = append(events, &InotifyEvent{
        Wd:     uint32(event.Wd),
        Name:   name,
        Path: filepath.Join(basePath, name),
        Mask:   event.Mask,
        Cookie: event.Cookie,
      })
      log.Printf("Event (%s): %s\n", basePath, events[len(events)-1])
    }
  }
}

func (w *InotifyWatcher) Process() {
  events, err := w.Read()
  defer func() {
    if events == nil {
      return
    }
    for i := range events {
      events[i] = nil // empty array
    }
    eventsPool.Put(events[:0]) // reset length, keep capacity
  }()
  if err != nil {
    log.Printf("ERROR: failed to read events: %v\n", err)
    return
  } else if len(events) == 0 {
    return
  }

  for _, event := range events {
    w.mu.RLock()
    wi, ok := w.watches[event.Wd]
    w.mu.RUnlock()
    if !ok {
      continue
    }
    if !w.isDir {
      idx, score := -1, -1
      for i, fi := range wi.files {
        if yes, err := filepath.Match(fi.name, event.Name); err != nil {
          log.Printf("ERROR: failed to match file name (%s) with pattern %q: %v\n", event.Name, fi.name, err)
          continue
        } else if yes && event.Mask&fi.mask != 0 && globScore(fi.name) > score {
          score = globScore(fi.name)
          idx = i
        }
      }
      if idx >= 0 {
        for _, fn := range wi.files[idx].update {
          go fn(event)
        }
      }
    } else {
      // Skip ignored events queued from removed watchers
      if event.Mask&unix.IN_IGNORED > 0 {
        continue
      }
      w.mu.RLock()
      wi, ok := w.watches[event.Wd]
      w.mu.RUnlock()
      if !ok {
        continue
      }
      fi := wi.files[0]
      // Add watch for folders created or moved into watched folders (recursion)
      const dirNewMask = unix.IN_CREATE | unix.IN_MOVED_TO
      if event.Mask&dirNewMask > 0 && event.Mask&unix.IN_ISDIR > 0 {
        // Wait for further files to be added
        err := w.addSubDirs(event.Path, fi.mask, fi.update...)
        if err != nil {
          log.Printf("ERROR: failed to add dir watch for %s: %v\n", event.Path, err)
        }
        continue
      }
      // Remove watch for deleted folders
      const dirRmMask = unix.IN_DELETE | unix.IN_MOVED_FROM | unix.IN_UNMOUNT
      if event.Mask&dirRmMask > 0 && event.Mask&unix.IN_ISDIR > 0 {
        for wd, wi := range w.watches { // remove thsi one and its subdirs
          if IsSubpath(event.Path, wi.basePath) {
            err := w.RemoveWd(wd, wi.basePath)
            if err != nil {
              log.Printf("ERROR: failed to remove dir watch for %s: %v\n", wi.basePath, err)
            }
          }
        }
        continue
      }
      // Skip sub-folder events
      if event.Mask&unix.IN_ISDIR > 0 {
        continue
      }
      // process file event
      if event.Mask&fi.mask != 0 {
        for _, fn := range fi.update {
          go fn(event)
        }
      }
    }
  }
}

// epoll stuff
type InotifyEpoller struct {
  ctx    context.Context
  mu sync.RWMutex
  fd       int               // File descriptor (as returned by the inotify_init() syscall)
  watchers  map[int]*InotifyWatcher // map of InotifyWatcher.fd (int) -> *InotifyWatcher 
  fileWatcher *InotifyWatcher // file watcher
}

func (ep *InotifyEpoller) String() string {
  var sb strings.Builder
  fmt.Fprintf(&sb, "InotifyEpoller (fd: %d):\n", ep.fd)
  for _, w := range ep.watchers {
    fmt.Fprintf(&sb, "  %s\n", w.ToString(2))
  }
  return sb.String()
}

func NewInotifyEpoller(ctx context.Context) (*InotifyEpoller, error) {
  epfd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
  if err != nil {
    return nil, fmt.Errorf("failed epoll_create1: %w", err)
  }
  e := &InotifyEpoller{
    ctx:    ctx,
    fd:      epfd,
    watchers: make(map[int]*InotifyWatcher),
  }
  go func() {
    <-ctx.Done()
    e.Close()
  }()
  return e, nil
}

func (e *InotifyEpoller) Close() error {
  e.mu.Lock()
  defer e.mu.Unlock()
  
  for _, iw := range e.watchers { // close all inotify watchers
    iw.Close()
  }
  e.watchers = nil
  err := unix.Close(e.fd)
  e.fd = -1
  return err
}

func (e *InotifyEpoller) AddWatch(iw *InotifyWatcher) error {
  var event unix.EpollEvent
  // We have IN_NONBLOCK set on watchers, use EPOLLET to get the maximum efficiency
  event.Events = unix.EPOLLIN|unix.EPOLLET
  event.Fd = int32(iw.fd)
  if err := unix.EpollCtl(e.fd, unix.EPOLL_CTL_ADD, iw.fd, &event); err != nil {
    return fmt.Errorf("failed epoll_ctl add wacher: %w", err)
  }
  log.Printf("Add watcher %d\n", iw.fd)
  e.mu.Lock()
  defer e.mu.Unlock()
  
  e.watchers[iw.fd] = iw
  return nil
}

func (e *InotifyEpoller) RemoveWatch(fd int) error {
  if err := unix.EpollCtl(e.fd, unix.EPOLL_CTL_DEL, fd, nil); err != nil {
    return fmt.Errorf("failed epoll_ctl remove wacher: %w", err)
  }
  e.mu.Lock()
  defer e.mu.Unlock()
  
  delete(e.watchers, fd)
  return nil
}

func (e *InotifyEpoller) Wait(timeout int) error {
  var events [MaxEpollEvents]unix.EpollEvent
  if timeout < 0 {
    timeout = -1
  }
  for {
    select {
    case <-e.ctx.Done():
      return e.ctx.Err()
    default: // unblock select if ctx.Done() is not ready
      n, err := unix.EpollWait(e.fd, events[:], timeout)
      if err != nil {
        // EINTR if interrupted by a signal or timeout expired
        if !errors.Is(err, unix.EINTR) {
          return fmt.Errorf("failed epoll_wait: %w", err)
        }
        continue
      } else if n == 0 {
        continue
      }
      var wg sync.WaitGroup
      for i := 0; i < n; i++ {
        ev := events[i]
        if ev.Events == 0 {
          continue
        } else if ev.Events != unix.EPOLLIN {
          log.Printf("Unexpected event: %#x\n", ev.Events)
          continue
        }
        e.mu.RLock()
        iw, ok := e.watchers[int(ev.Fd)]
        e.mu.RUnlock()
        if ok {
          wg.Add(1)
          go func() {
            iw.Process()
            wg.Done()
          }()
        }
      }
      wg.Wait()
    }
  }
}

func (e *InotifyEpoller) AddFileWatch(pathName string, mask uint32, fns ...UpdateFn) error {
  if len(fns) == 0 {
    return fmt.Errorf("fns cannot be empty")
  } else {
    for i, fn := range fns {
      if fn == nil {
        return fmt.Errorf("fns[%d] cannot be nil", i)
      }
    }
  }
  var err error
  var fw *InotifyWatcher
  e.mu.RLock()
  fw = e.fileWatcher
  e.mu.RUnlock()
  if fw == nil {
    fw, err = NewInotifyWatcher(false)
    if err != nil {
      return err
    }
    if err = e.AddWatch(fw); err != nil {
      return err
    }
    e.mu.Lock()
    e.fileWatcher = fw
    e.mu.Unlock()
  }
  return fw.AddFileWatch(pathName, mask, fns...)
}

func (e *InotifyEpoller) AddDirWatch(pathName string, mask uint32, fns ...UpdateFn) error {
  if len(fns) == 0 {
    return fmt.Errorf("fns cannot be empty")
  } else {
    for i, fn := range fns {
      if fn == nil {
        return fmt.Errorf("fns[%d] cannot be nil", i)
      }
    }
  }
  var err error
  var dw *InotifyWatcher
  e.mu.RLock()
  for _, iw := range e.watchers {
    if iw.isDir { 
      if len(iw.watches) == 0 { // reuse it
        dw.dirPath = "" // clear it to be able to reuse it!
        if dw == nil {
          dw = iw
        }
      }
      if pathName == iw.dirPath {
        dw = iw
        break
      }
    }
  }
  e.mu.RUnlock()
  if dw == nil { // create a new one
    dw, err = NewInotifyWatcher(true)
    if err != nil {
      return err
    }
    if err = e.AddWatch(dw); err != nil {
      return err
    }
  }
  return dw.AddDirWatch(pathName, mask, fns...)
}
