package extract

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"io"
	"time"
)

type cfFolder struct {
	coffCabStart uint32
	cCFData      uint16
	typeCompress uint16
}

type cfFile struct {
	cbFile          uint32
	uoffFolderStart uint32
	iFolder         uint16
	name            string
}

// unpackCab extracts members from a Microsoft Cabinet (MSCF) archive.
func unpackCab(buf []byte, res *Result, b *archiveBudget, depth int, deadline time.Time) {
	if len(buf) < 36 {
		return
	}
	if !bytes.HasPrefix(buf, cabMagic) {
		return
	}

	res.IsArchive = true

	coffFiles := binary.LittleEndian.Uint32(buf[16:20])
	cFolders := binary.LittleEndian.Uint16(buf[26:28])
	cFiles := binary.LittleEndian.Uint16(buf[28:30])
	flags := binary.LittleEndian.Uint16(buf[30:32])

	if int(cFolders) > maxArchiveMembers {
		cFolders = maxArchiveMembers
	}
	if int(cFiles) > maxArchiveMembers {
		cFiles = maxArchiveMembers
	}

	var cbCFFolder uint8
	var cbCFData uint8
	reserveHeaderExtra := 0
	if flags&0x0004 != 0 {
		if len(buf) < 40 {
			return
		}
		cbCFHeaderExtra := binary.LittleEndian.Uint16(buf[36:38])
		cbCFFolder = buf[38]
		cbCFData = buf[39]
		reserveHeaderExtra = 4 + int(cbCFHeaderExtra)
	}

	folderEntrySize := 8 + int(cbCFFolder)
	foldersTotal := int(cFolders) * folderEntrySize

	// Compare in int — foldersTotal is bounded (cFolders ≤ maxArchiveMembers,
	// folderEntrySize ≤ 8+255) and coffFiles is a uint32 that always fits int on a
	// 64-bit host, so this avoids the int→uint32 narrowing gosec flags (G115).
	if foldersTotal > int(coffFiles) {
		return
	}
	folderArrayOffset := int(coffFiles) - foldersTotal

	minFolderOffset := 36 + reserveHeaderExtra
	if folderArrayOffset < minFolderOffset {
		return
	}

	if len(buf) < folderArrayOffset+foldersTotal {
		return
	}

	folders := make([]cfFolder, int(cFolders))
	for i := 0; i < int(cFolders); i++ {
		off := folderArrayOffset + i*folderEntrySize
		folders[i] = cfFolder{
			coffCabStart: binary.LittleEndian.Uint32(buf[off : off+4]),
			cCFData:      binary.LittleEndian.Uint16(buf[off+4 : off+6]),
			typeCompress: binary.LittleEndian.Uint16(buf[off+6 : off+8]),
		}
	}

	if uint64(coffFiles) >= uint64(len(buf)) {
		return
	}
	files := make([]cfFile, 0, int(cFiles))
	pos := int(coffFiles)
	for i := 0; i < int(cFiles); i++ {
		if pos+16 > len(buf) {
			break
		}
		cbFile := binary.LittleEndian.Uint32(buf[pos : pos+4])
		uoffFolderStart := binary.LittleEndian.Uint32(buf[pos+4 : pos+8])
		iFolder := binary.LittleEndian.Uint16(buf[pos+8 : pos+10])
		pos += 16
		end := bytes.IndexByte(buf[pos:], 0)
		if end < 0 {
			break
		}
		name := string(buf[pos : pos+end])
		pos += end + 1
		files = append(files, cfFile{
			cbFile:          cbFile,
			uoffFolderStart: uoffFolderStart,
			iFolder:         iFolder,
			name:            name,
		})
	}

	cabUnsupportedEmitted := false

	for fi, folder := range folders {
		if expired(deadline) || b.spent() || len(res.Streams) >= maxStreams {
			break
		}

		compType := folder.typeCompress & 0xFF

		if compType == 0x02 || compType == 0x03 {
			if !cabUnsupportedEmitted {
				cabUnsupportedEmitted = true
				res.Streams = append(res.Streams, []byte("CAB-COMPRESSION-UNSUPPORTED"))
			}
			continue
		}

		folderData := decompressCabFolder(buf, folder, cbCFData, uint8(compType))

		for _, f := range files {
			if int(f.iFolder) != fi {
				continue
			}
			if expired(deadline) || b.spent() || len(res.Streams) >= maxStreams {
				break
			}

			start := int(f.uoffFolderStart)
			fileEnd := start + int(f.cbFile)

			if start > len(folderData) {
				start = len(folderData)
			}
			if fileEnd > len(folderData) {
				fileEnd = len(folderData)
			}
			if fileEnd > start+maxBytesPerMember {
				fileEnd = start + maxBytesPerMember
			}

			member := folderData[start:fileEnd]
			if len(member) == 0 {
				continue
			}

			emitMember(member, res, b, depth, deadline)
		}
	}
}

// decompressCabFolder reads and decompresses all CFDATA blocks for a folder.
// Returns raw concatenated folder data (up to maxBytesPerMember bytes).
func decompressCabFolder(buf []byte, folder cfFolder, cbCFData uint8, compType uint8) []byte {
	dataOffset := int(folder.coffCabStart)
	nBlocks := int(folder.cCFData)
	perBlockReserved := int(cbCFData)

	folderData := make([]byte, 0, 4096)
	mszipDict := make([]byte, 0, 32768)

	for i := 0; i < nBlocks; i++ {
		if dataOffset+8+perBlockReserved > len(buf) {
			break
		}
		cbData := int(binary.LittleEndian.Uint16(buf[dataOffset+4 : dataOffset+6]))
		// cbUncomp unused — we decompress until exhausted.

		compStart := dataOffset + 8 + perBlockReserved
		compEnd := compStart + cbData
		if compEnd > len(buf) {
			break
		}

		compressedBlock := buf[compStart:compEnd]

		switch compType {
		case 0x00: // NONE — data is stored as-is.
			remaining := maxBytesPerMember - len(folderData)
			if remaining <= 0 {
				return folderData
			}
			take := len(compressedBlock)
			if take > remaining {
				take = remaining
			}
			folderData = append(folderData, compressedBlock[:take]...)
			if len(folderData) >= maxBytesPerMember {
				return folderData
			}

		case 0x01: // MSZIP: "CK" + raw DEFLATE with 32K sliding window.
			if len(compressedBlock) < 2 || compressedBlock[0] != 0x43 || compressedBlock[1] != 0x4B {
				// Corrupt block — skip.
				break
			}
			deflateData := compressedBlock[2:]

			var r io.ReadCloser
			if len(mszipDict) > 0 {
				r = flate.NewReaderDict(bytes.NewReader(deflateData), mszipDict)
			} else {
				r = flate.NewReader(bytes.NewReader(deflateData))
			}

			limit := maxBytesPerMember - len(folderData)
			if limit <= 0 {
				_ = r.Close()
				return folderData
			}
			decompressed, _ := io.ReadAll(io.LimitReader(r, int64(limit)))
			_ = r.Close()

			// Update the 32K MSZIP sliding-window dict for the NEXT block. Build it
			// into a fresh slice (never append into the dict the previous
			// flate.NewReaderDict still aliases) so a future block's reader can't
			// observe a mutated backing array.
			if len(decompressed) > 0 {
				combined := make([]byte, 0, len(mszipDict)+len(decompressed))
				combined = append(combined, mszipDict...)
				combined = append(combined, decompressed...)
				if len(combined) > 32768 {
					combined = combined[len(combined)-32768:]
				}
				mszipDict = combined

				folderData = append(folderData, decompressed...)
				if len(folderData) >= maxBytesPerMember {
					return folderData
				}
			}
		}

		dataOffset = compEnd
	}

	return folderData
}
