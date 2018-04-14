package virtualmachine

import (
	"crypto/md5"
	"crypto/sha1"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

// GetISO returns a path on the local filesystem to the latest version of the Arch Linux ISO, it also performs
// verification of MD5 checksum, SHA1 checksum, and the PGP signature.
func GetISO() (string, error) {
	return getISO()
}

type ArchVersion struct {
	CurrentRelease       string
	IncludedKernel       string
	ISOSizeOfficial      string
	ISOSize              int64
	ISOFileName          string
	ISOSignatureFileName string
	PGPSignatureFile     string
	MD5Checksum          string
	SHA1Checksum         string
}

type Mirror struct {
	ArchVersion
	Name       string
	ISOFileURI string
}

type PGPPublicKeyMeta struct {
	KeyID       string
	Fingerprint string
}

func mirrorList() []Mirror {
	version := ArchVersion{
		CurrentRelease:       "2018.04.01",
		IncludedKernel:       "4.15.14",
		ISOSizeOfficial:      "556.0MB",
		ISOSize:              583008256,
		ISOFileName:          "archlinux-2018.04.01-x86_64.iso",
		ISOSignatureFileName: "archlinux-2018.04.01-x86_64.iso.sig",
		PGPSignatureFile:     "data/archlinux/archlinux-2018.04.01-x86_64.iso.sig",
		MD5Checksum:          "3499f11c7c56a64fb75661b7f08da541",
		SHA1Checksum:         "42cf488fb6cba31c57f8ad875cb03784760c4b94",
	}

	return []Mirror{
		{
			ArchVersion: version,
			Name:        "internode.on.net",
			ISOFileURI:  "http://mirror.internode.on.net/pub/archlinux/iso/2018.04.01/archlinux-2018.04.01-x86_64.iso",
		},
	}
}

func getISO() (string, error) {
	for _, mirror := range mirrorList() {
		location, err := downloadISO(mirror, "")
		if err != nil {
			log.Println(err)
			continue
		}

		return location, nil
	}

	return "", errors.New("unable to download ISO")
}

func checkISO(version ArchVersion, filePath string) error {

	f, err := os.Open(filePath)
	if err != nil {
		return err
	}

	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if fi.Size() != version.ISOSize {
		return errors.New(fmt.Sprintf("expected filesize to be %d B, but was %d B", version.ISOSize, fi.Size()))
	}

	fileData := make([]byte, fi.Size())
	_, err = f.Read(fileData)
	if err != nil {
		return err
	}

	// Check MD5 sum
	md5sum := fmt.Sprintf("%x", md5.Sum(fileData))
	if md5sum != version.MD5Checksum {
		return errors.New(
			fmt.Sprintf("MD5 checksum of %s failed:\n\texpected: %s\n\treceived%s",
				version.MD5Checksum, md5sum, filePath))
	}

	// Check SHA1 sum
	shasum := fmt.Sprintf("%x", sha1.Sum(fileData))
	if shasum != version.SHA1Checksum {
		return errors.New(
			fmt.Sprintf("SHA1 checksum of %s failed:\n\texpected: %s\n\treceived%s",
				version.SHA1Checksum, shasum, filePath))
	}

	// TODO Check PGP Signature - https://www.archlinux.org/master-keys/
	// This involves checking the signature, revocation, maintaining a list of the master keys, etc...

	return nil
}

// TODO ensure that we are in a safe download directory; some systems might not use the standard /tmp directory, or
// TODO    the user may provide a directory that is // not readable/writable.
// TODO ensure that the downloadDirectory is clean
// TODO make the downloads atomic. i.e. Move the file to the intended location after downloading it first.
// TODO validate the configuration. i.e. Does the filename match the name of the file we are downloading?
func downloadISO(mirror Mirror, downloadDirectory string) (string, error) {
	if downloadDirectory == "" {
		downloadDirectory = "/tmp/arch_workstation"
	}

	if err := os.MkdirAll(downloadDirectory, 0700); err != nil {
		return "", err
	}

	isoFilePath := filepath.Join(downloadDirectory, mirror.ArchVersion.ISOFileName)

	if err := checkISO(mirror.ArchVersion, isoFilePath); err == nil {
		return isoFilePath, nil
	}

	log.Printf("downloading %s from %s", mirror.ArchVersion.ISOFileName, mirror.Name)

	isoFile, err := os.Create(isoFilePath)
	if err != nil {
		return "", err
	}
	defer isoFile.Close()

	isoResponse, err := http.Get(mirror.ISOFileURI)
	if err != nil {
		return "", errors.New(
			fmt.Sprintf("error downloading %s from %s: %v", mirror.ArchVersion.ISOFileName, mirror.Name, err))
	}
	defer isoResponse.Body.Close()

	if isoResponse.StatusCode != http.StatusOK {
		return "", errors.New(
			fmt.Sprintf("error downloading %s from %s: status code %d",
				mirror.ArchVersion.ISOFileName,
				mirror.Name,
				isoResponse.StatusCode,
			))
	}

	_, err = io.Copy(isoFile, isoResponse.Body)
	if err != nil {
		return "", errors.New(
			fmt.Sprintf("error saving %s from %s: %v", mirror.ArchVersion.ISOFileName, mirror.Name, err))
	}

	return isoFilePath, nil
}
