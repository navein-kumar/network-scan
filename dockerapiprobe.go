// dockerapiprobe.go: phase 3 driver for Docker remote API (2375 cleartext,
// 2376 TLS).
//
// stdlib HTTP GET /version + GET /containers/json?all=true. An anonymous
// 200 on /version means the Docker socket is reachable without auth, and
// an anonymous 200 on /containers/json is full container control surface.
package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type DockerAPIReport struct {
	Host                 string   `json:"host"`
	Port                 int      `json:"port"`
	Reachable            bool     `json:"reachable"`
	IsTLS                bool     `json:"is_tls"`
	APIVersion           string   `json:"api_version,omitempty"`
	Version              string   `json:"version,omitempty"`
	OS                   string   `json:"os,omitempty"`
	Arch                 string   `json:"arch,omitempty"`
	KernelVersion        string   `json:"kernel_version,omitempty"`
	ContainersAccessible bool     `json:"containers_accessible"`
	ContainerCount       int      `json:"container_count,omitempty"`
	Containers           []string `json:"containers,omitempty"`
	Images               []string `json:"images,omitempty"`
	ProbeErrors          []string `json:"probe_errors,omitempty"`
}

func ProbeDockerAPI(host string, port int, timeout time.Duration) (*DockerAPIReport, error) {
	rep := &DockerAPIReport{Host: host, Port: port}
	scheme := "http"
	if port == 2376 {
		rep.IsTLS = true
		scheme = "https"
	}
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
	}
	cli := &http.Client{Timeout: timeout, Transport: tr}

	verURL := fmt.Sprintf("%s://%s:%d/version", scheme, host, port)
	resp, err := cli.Get(verURL)
	if err != nil {
		// Try opposite scheme as a fallback (port may be reused).
		if scheme == "http" {
			scheme = "https"
			rep.IsTLS = true
		} else {
			scheme = "http"
			rep.IsTLS = false
		}
		verURL = fmt.Sprintf("%s://%s:%d/version", scheme, host, port)
		resp, err = cli.Get(verURL)
		if err != nil {
			return rep, fmt.Errorf("get /version: %w", err)
		}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == 200 {
		var v struct {
			APIVersion    string `json:"ApiVersion"`
			Version       string `json:"Version"`
			Os            string `json:"Os"`
			Arch          string `json:"Arch"`
			KernelVersion string `json:"KernelVersion"`
		}
		if err := json.Unmarshal(body, &v); err == nil && v.APIVersion != "" {
			rep.Reachable = true
			rep.APIVersion = v.APIVersion
			rep.Version = v.Version
			rep.OS = v.Os
			rep.Arch = v.Arch
			rep.KernelVersion = v.KernelVersion
		}
	}
	if !rep.Reachable {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("/version status=%d", resp.StatusCode))
		return rep, nil
	}

	// Containers probe.
	cURL := fmt.Sprintf("%s://%s:%d/containers/json?all=true", scheme, host, port)
	cresp, cerr := cli.Get(cURL)
	if cerr != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("get /containers: %v", cerr))
		return rep, nil
	}
	defer cresp.Body.Close()
	cbody, _ := io.ReadAll(io.LimitReader(cresp.Body, 1<<20))
	if cresp.StatusCode == 200 {
		var arr []struct {
			Names []string `json:"Names"`
			Image string   `json:"Image"`
			State string   `json:"State"`
		}
		if err := json.Unmarshal(cbody, &arr); err == nil {
			rep.ContainersAccessible = true
			rep.ContainerCount = len(arr)
			for _, c := range arr {
				if len(rep.Containers) >= 50 {
					break
				}
				name := ""
				if len(c.Names) > 0 {
					name = c.Names[0]
					if len(name) > 0 && name[0] == '/' {
						name = name[1:]
					}
				}
				rep.Containers = append(rep.Containers,
					fmt.Sprintf("%s  %s (%s)", name, c.Image, c.State))
			}
		}
	}

	// Images probe: full image inventory is part of the control surface.
	iURL := fmt.Sprintf("%s://%s:%d/images/json", scheme, host, port)
	iresp, ierr := cli.Get(iURL)
	if ierr != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("get /images: %v", ierr))
		return rep, nil
	}
	defer iresp.Body.Close()
	ibody, _ := io.ReadAll(io.LimitReader(iresp.Body, 1<<20))
	if iresp.StatusCode == 200 {
		var arr []struct {
			RepoTags []string `json:"RepoTags"`
			Id       string   `json:"Id"`
		}
		if err := json.Unmarshal(ibody, &arr); err == nil {
			for _, im := range arr {
				if len(rep.Images) >= 50 {
					break
				}
				tags := ""
				for _, t := range im.RepoTags {
					if t != "" && t != "<none>:<none>" {
						if tags != "" {
							tags += ", "
						}
						tags += t
					}
				}
				if tags == "" {
					id := im.Id
					if len(id) > 19 {
						id = id[:19]
					}
					tags = "<none> " + id
				}
				rep.Images = append(rep.Images, tags)
			}
		}
	}
	return rep, nil
}
