package main

import (
	"fmt"
	"path/filepath"
	"time"
	"log"
	"context"
	"os"
	"sync"
	"sync/atomic"
	"golang.org/x/sys/unix"
	"github.com/awnumar/memguard"
)

const (
	dataFile = "..data"
	specialFile = "test.txt"

	certContent  = "This is a test cert."
	cert1Content = "This is a test cert1."
	conf1Content = "This is the test #1 conf."
	conf2Content = "This is the test #2 conf."
)

type Handler struct {
	path string
	special  atomic.Pointer[memguard.Enclave]
}

func NewHandler(path string) (*Handler, error) {
	h := &Handler{path: path}
	if err := h.Set(nil); err != nil {
		return nil, fmt.Errorf("failed to set special: %w", err)
	}
	return h, nil
}

func (h *Handler) Get() (string, error) {
	lb, err := h.special.Load().Open()
	if err != nil {
		return "", fmt.Errorf("failed to read special from enclave: %w", err)
	}
	defer lb.Destroy()
	// Need to clone/copy lb.String(); otherwise, the underlying string storage is gone after the lb si destroied!
	// strings.Clone() or fmt.SPrintf() would do it
	return fmt.Sprintf("%s", lb.String()), nil
}

func (h *Handler) Set(old *memguard.Enclave) error {
	data, err := os.ReadFile(h.path)
	if err != nil {
		return fmt.Errorf("failed to read special file %q: %w", h.path, err)
	}
	new := memguard.NewEnclave(data)
	if old == nil {
		h.special.Store(new)
		log.Printf("-> Special updated\n")
	} else if h.special.CompareAndSwap(old, new) {
		log.Printf("-> Special updated from old\n")
	} else {
		log.Printf("-> Unable to update Special: already updated\n")
	}
	return nil
}

func (h *Handler) Update(event *InotifyEvent) {
	const updateEvents = unix.IN_MOVED_TO|unix.IN_CREATE
	if event.Mask&updateEvents == 0 {
		return
	}
	if err := h.Set(h.special.Load()); err != nil {
		log.Printf("* failed to update special on event %s: %v\n", event, err)
	} else {
		log.Printf("* updated special on event %s\n", event)
	}
}

func newTextFile(thePath, content string) error {
	fp, err := os.Create(thePath)
	if err != nil {
		return fmt.Errorf("failed create %q: %w", thePath, err)
	}
	defer fp.Close()
	if _, err := fp.WriteString(content); err != nil {
		return fmt.Errorf("failed write content to %q: %w", thePath, err)
	}
	return nil
}

func SetupDirs() string {
	var hasErr bool
	baseDir, err := os.MkdirTemp("", "")
	if err != nil {
		log.Fatalf("Error creating temp directory: %v", err)
	}
	defer func() {
		if hasErr {
			os.RemoveAll(baseDir)
		}
	}()
	confDir := baseDir + "/conf"
	certDir := baseDir + "/certs"

	if err := os.MkdirAll(certDir+"/temp", 0755); err != nil {
		hasErr = true
		log.Fatalf("failed to setup dirs when creating temp in certDir: %v!", err)
	}
	if err := newTextFile(certDir+"/test.crt", certContent); err != nil {
		hasErr = true
		log.Fatalf("failed to set up file test.crt in certDir: %v!", err)
	}
	if err := os.MkdirAll(confDir+"/..t1", 0755); err != nil {
		hasErr = true
		log.Fatalf("failed to setup dirs when creating ..t1 in confDir: %v!", err)
	}
	if err := newTextFile(confDir+"/..t1/test.txt", conf1Content); err != nil {
		hasErr = true
		log.Fatalf("failed to set up file ..t1/test.txt in confDir: %v!", err)
	}
	if err := os.MkdirAll(confDir+"/..t2", 0755); err != nil {
		hasErr = true
		log.Fatalf("failed to setup dirs when creating ..t2 in confDir: %v!", err)
	}
	if err := newTextFile(confDir+"/..t2/test.txt", conf2Content); err != nil {
		hasErr = true
		log.Fatalf("failed to set up file ..t2/test.txt in confDir: %v!", err)
	}
	if err := os.Symlink("..t1", confDir+"/..data"); err != nil {
		hasErr = true
		log.Fatalf("failed to set up symlink file ..data in confDir: %v!", err)
	}
	if err := os.Symlink("..data/test.txt", filepath.Join(confDir, specialFile)); err != nil {
		hasErr = true
		log.Fatalf("failed to set up symlink file test.txt in confDir: %v!", err)
	}
	return baseDir
}

func ModConf(baseDir string, useRename bool) {
	confDir := baseDir + "/conf"
	s, err := os.Readlink(confDir+ "/..data")
	if err != nil {
		log.Printf("ERROR: Failed read ..data: %v\n", err)
	}
	dest := "..t2"
	if s == "..t2" {
		dest = "..t1"
	}
	if useRename {
		if err := os.Symlink(dest, baseDir+ "/..data"); err != nil {
			log.Printf("ERROR: Failed modify ..data: %v\n", err)
		}
		log.Printf("> Symlink ..data in\n")
		if err := os.Rename(baseDir+ "/..data", confDir+ "/..data"); err != nil {
			log.Printf("ERROR: Failed rename ..data: %v\n", err)
		}
	} else {
		log.Printf("> Remove symlink ..data inside\n")
		if err := os.Remove(confDir+ "/..data"); err != nil {
			log.Printf("ERROR: Failed remove ..data: %v\n", err)
		}
		log.Printf("> Symlink ..data inside\n")
		if err := os.Symlink(dest, confDir+ "/..data"); err != nil {
			log.Printf("ERROR: Failed re-link ..data: %v\n", err)
		}
	}
}

func ModCert(baseDir string, useRename bool, ep *InotifyEpoller) {
	certDir := baseDir + "/certs"
	if useRename {
		fp, err := os.Create(baseDir+"/test.crt1")
		if err != nil {
			log.Printf("ERROR: Failed create test.crt1: %v\n", err)
		}
		defer fp.Close()
		if _, err := fp.WriteString("test me"); err != nil {
			log.Printf("ERROR: Failed write test.crt1: %v\n", err)
		}
		fp.Close()
		log.Printf("> Rename test.cert in\n")
		if err := os.Rename(baseDir+"/test.crt1", certDir+"/test.crt"); err != nil {
			log.Printf("ERROR: Failed rename test.crt1 to test.crt: %v\n", err)
		}
		log.Printf("> Rename temp/ out\n")
		if err := os.Rename(certDir+"/temp", baseDir+"/temp"); err != nil {
			log.Printf("ERROR: Failed move away temp: %v\n", err)
		}
		time.Sleep(300*time.Millisecond)
		log.Printf("Epoll: %s\n", ep)
		log.Printf("> Rename temp/ in\n")
		if err := os.Rename(baseDir+"/temp", certDir+"/temp"); err != nil {
			log.Printf("ERROR: Failed move into temp: %v\n", err)
		}
		time.Sleep(300*time.Millisecond)
		log.Printf("Epoll: %s\n", ep)
	} else {
		log.Printf("> Remove test.cert inside\n")
		if err := os.Remove(certDir+"/test.crt"); err != nil {
			log.Printf("ERROR: Failed remove test.crt: %v\n", err)
		}
		log.Printf("> Create test.cert inside\n")
		fp, err := os.Create(certDir+"/test.crt")
		if err != nil {
			log.Printf("ERROR: Failed create test.crt: %v\n", err)
		}
		defer fp.Close()
		if _, err := fp.WriteString("test me"); err != nil {
			log.Printf("ERROR: Failed write test.crt: %v\n", err)
		}
		fp.Close()
		log.Printf("> Remove temp/ inside\n")
		if err := os.Remove(certDir+"/temp"); err != nil {
			log.Printf("ERROR: Failed move delete temp: %v\n", err)
		}
		time.Sleep(300*time.Millisecond)
		log.Printf("Epoll: %s\n", ep)
		log.Printf("> Mkdir temp/ inside\n")
		if err := os.Mkdir(certDir+"/temp", 0777); err != nil {
			log.Printf("ERROR: Failed mkdir temp: %v\n", err)
		}
		time.Sleep(300*time.Millisecond)
		log.Printf("Epoll: %s\n", ep)
	} 
	log.Printf("> Mount tempM/\n")
	if err := unix.Mount("tmpfs", certDir+"/tempM", "tmpfs", 0, ""); err != nil {
		log.Printf("ERROR: Failed mount tempM: %v\n", err)
	}
	time.Sleep(300*time.Millisecond)
	log.Printf("> unmount tempM/\n")
	if err := unix.Unmount(certDir+"/tempM", 0); err != nil {
		log.Printf("ERROR: Failed unmount tempM: %v\n", err)
	}
	time.Sleep(300*time.Millisecond)
	log.Printf("Epoll: %s\n", ep)
}

func ShowSpecial(h *Handler) {
	if s, err := h.Get(); err != nil {
		log.Printf("ERROR: unable to read Special: %v\n", err)
	} else {
		log.Printf("** Special: %s\n", s)
	}
}

func main() {
	baseDir := SetupDirs()
	defer os.RemoveAll(baseDir)

	confDir := baseDir + "/conf"
	certDir := baseDir + "/certs"
	specialPath := filepath.Join(confDir, specialFile)
	h, err := NewHandler(specialPath)
	if err != nil {
		panic(err)
	}
	
	ctx, cancel := context.WithCancel(context.Background())

	ep, err := NewInotifyEpoller(ctx)
	if err != nil {
		panic(err)
	}

	go ep.Wait(10)

	err = ep.AddFileWatch(confDir+"/..data", 
		unix.IN_CREATE|unix.IN_DELETE|unix.IN_CLOSE_WRITE|unix.IN_MOVE|unix.IN_DONT_FOLLOW /*unix.IN_ALL_EVENTS*/, 
		func(event *InotifyEvent) {
			log.Printf("event for confDir: %s\n", event)
			h.Update(event)
		})
	if err != nil {
		panic(err)
	}

	/*err = ep.AddFileWatch(certDir+"/*.crt", 
		unix.IN_CREATE|unix.IN_DELETE|unix.IN_CLOSE_WRITE|unix.IN_MOVE, 
		func(event *InotifyEvent) {
			log.Printf("event for CertDir FileWatcher: %s\n", event)
		})
	if err != nil {
		panic(err)
	}*/

	err = ep.AddDirWatch(certDir, 
		unix.IN_CREATE|unix.IN_DELETE|unix.IN_CLOSE_WRITE|unix.IN_MOVE /*unix.IN_ALL_EVENTS*/, 
		func(event *InotifyEvent) {
			log.Printf("event for CertDir DirWatcher: %s\n", event)
		})
	if err != nil {
		panic(err)
	}


	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		ShowSpecial(h)
		time.Sleep(time.Second)
		ModConf(baseDir, true)
		time.Sleep(100*time.Millisecond)
		ShowSpecial(h)
		
		time.Sleep(time.Second)
		ModCert(baseDir, true, ep)
		
		time.Sleep(time.Second)
		ModConf(baseDir, false)
		time.Sleep(100*time.Millisecond)
		ShowSpecial(h)

		time.Sleep(time.Second)
		ModCert(baseDir, false, ep)
		
		time.Sleep(time.Second)
		ModConf(baseDir, true)
		time.Sleep(100*time.Millisecond)
		ShowSpecial(h)
		time.Sleep(2 *time.Second)
		fmt.Println("Done testing!")
		wg.Done()
	}()
	wg.Wait()
	fmt.Printf("Epoll: %s\n", ep)
	fmt.Println("Time is up!")
	fmt.Printf("Mask: %s\n", InMaskToString(0xffffffff))
	cancel()
}
