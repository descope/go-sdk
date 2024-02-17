package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/descope/go-sdk/descope"
)

func ImportUsers(args []string) (err error) {
	source := args[0]

	if Flags.Dryrun {
		printMessage("• Starting dry run for source %s", source)
	} else {
		printMessage("• Starting import for source %s", source)
	}

	var users, hashes []byte
	if Flags.Users != "" {
		printMessage("• Reading users data...")
		if users, err = readFile(Flags.Users); err != nil {
			return err
		}
	}
	if Flags.Hashes != "" {
		printMessage("• Reading hashes data...")
		if hashes, err = readFile(Flags.Hashes); err != nil {
			return err
		}
	}

	if len(hashes) > 0 && len(users) == 0 {
		return ImportHashes(source, hashes)
	}

	_, err = importBatch(source, users, hashes)
	return err
}

func ImportHashes(source string, hashes []byte) error {
	batches := [][]byte{}
	batch := []byte{}
	count := 0
	total := 0

	s := bufio.NewScanner(bytes.NewReader(hashes))
	for s.Scan() {
		total++
		count++
		value := s.Bytes()
		batch = append(batch, value...)
		batch = append(batch, "\n"...)
		if count >= Flags.Batch {
			batches = append(batches, batch)
			batch = []byte{}
			count = 0
		}
	}
	if err := s.Err(); err != nil {
		return fmt.Errorf("failed to parse hashes for batching: %w", err)
	}

	if len(batch) > 0 {
		batches = append(batches, batch)
	}

	if total == 0 {
		printJson("{}")
		printMessage("• No users found")
		printMessage("• Done")
		return nil
	}

	if len(batches) == 1 {
		printMessage("• Importing %d users...", total)
	} else {
		printMessage("• Found %d users", total)
		printMessage("• Importing %d batches of up to %d users each", len(batches), Flags.Batch)
	}

	users := 0
	failures := 0

	printJson("[")
	for i, batch := range batches {
		if len(batches) > 1 {
			printMessage("• Sending batch %d...", i+1)
		}

		res, err := importBatch(source, nil, batch)
		if err != nil {
			return err
		}

		users += len(res.Users)
		failures += len(res.Failures)

		if len(batches) > 1 && len(res.Failures) > 0 {
			ustring := "no users"
			if len(res.Users) == 1 {
				ustring = "1 user"
			} else if len(res.Users) > 1 {
				ustring = fmt.Sprintf("%d users", len(res.Users))
			}

			fstring := "no failures"
			if len(res.Failures) == 1 {
				fstring = "1 failure"
			} else if len(res.Failures) > 1 {
				fstring = fmt.Sprintf("%d failures", len(res.Failures))
			}

			printMessage("    - Batch finished with %s imported and %s", ustring, fstring)
		}

		if len(res.Users) > 0 && Flags.Verbose {
			printMessage("    - Imported users:")
			for _, user := range res.Users {
				printMessage("        · %v: %s", user.CustomAttributes["migrationUserId"], user.LoginIDs[0])
			}
		}

		if len(res.Failures) > 0 {
			printMessage("    - Failed users:")
			for _, failure := range res.Failures {
				printMessage("        · %s: %s", failure.User, failure.Reason)
			}
		}

		json, err := json.MarshalIndent(res, "  ", "  ")
		if err != nil {
			return fmt.Errorf("failed to format import response: %w", err)
		}
		jsonString := "  " + string(json)
		if i+1 < len(batches) {
			jsonString += ","
		}
		printJson(jsonString)
	}

	printJson("]")

	ustring := "no users"
	if users == 1 {
		ustring = "1 user"
	} else if users > 1 {
		ustring = fmt.Sprintf("%d users", users)
	}

	fstring := "no failures"
	if failures == 1 {
		fstring = "1 failure"
	} else if failures > 1 {
		fstring = fmt.Sprintf("%d failures", failures)
	}

	if len(batches) > 1 {
		printMessage("• Finished all batches with %s imported and %s", ustring, fstring)
	} else {
		printMessage("• Import finished with %s imported and %s", ustring, fstring)
	}

	printMessage("• Done")

	return nil
}

func importBatch(source string, users, hashes []byte) (*descope.UserImportResponse, error) {
	res, err := descopeClient.Management.User().Import(source, users, hashes, Flags.Dryrun)
	if err != nil {
		return nil, fmt.Errorf("failed to import users: %w", err)
	}
	return res, nil
}

func printJson(s string) {
	if Flags.Json {
		fmt.Println(s)
	}
}

func printMessage(format string, a ...any) {
	if !Flags.Json {
		fmt.Fprintf(os.Stderr, format+"\n", a...)
	}
}

func readFile(path string) ([]byte, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read input file %s: %w", path, err)
	}
	return bytes, nil
}
