package cli

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"pwnlibc/internal/elfinfo"
	"pwnlibc/internal/libcrip"
	"pwnlibc/internal/packages"
)

func newSearchCmd() *cobra.Command {
	var (
		libcPath string
		symbols  []string
		endsWith string
		str      string
		buildID  string
		tol      int
	)

	cmd := &cobra.Command{
		Use:   "search [query]",
		Short: "Search available versions by name, local symbols, or reverse symbol/BuildID lookup",
		RunE: func(cmd *cobra.Command, args []string) error {
			switch {
			case libcPath != "":
				return searchLocal(libcPath, symbols, endsWith, str)
			case buildID != "":
				return searchByBuildID(buildID)
			case len(symbols) > 0:
				return searchBySymbols(symbols, tol)
			case len(args) > 0:
				return searchByVersion(args[0])
			default:
				return fmt.Errorf("provide a version query, --libc, --symbol, or --buildid")
			}
		},
	}

	cmd.Flags().StringVar(&libcPath, "libc", "", "local ELF file to inspect instead of querying mirrors")
	cmd.Flags().StringArrayVar(&symbols, "symbol", nil, "symbol name (with --libc, supports glob) or name=addr (without --libc, for reverse lookup)")
	cmd.Flags().StringVar(&endsWith, "ends-with", "", "with --libc: only symbols whose offset hex ends with this suffix")
	cmd.Flags().StringVar(&str, "str", "", "with --libc: scan .rodata/.data for this string")
	cmd.Flags().StringVar(&buildID, "buildid", "", "reverse lookup by BuildID hex")
	cmd.Flags().IntVar(&tol, "tol", 0, "±byte tolerance when reverse-matching multiple symbol addresses")

	return cmd
}

func searchByBuildID(buildID string) error {
	idx, err := app.OpenIndex()
	if err != nil {
		return err
	}
	defer func() { _ = idx.Close() }()

	if versionArch, ok := idx.LookupBuildID(buildID); ok {
		app.EmitResult(map[string]interface{}{"source": "local", "version_arch": versionArch}, func() {
			fmt.Printf("%-24s (local index)\n", versionArch)
		})
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	matches, err := libcrip.NewClient().FindByBuildID(ctx, buildID)
	if err != nil {
		return err
	}
	app.EmitResult(matches, func() {
		if len(matches) == 0 {
			fmt.Println("no match locally or on libc.rip")
			return
		}
		for _, m := range matches {
			fmt.Printf("%-24s buildid=%s (libc.rip)\n", m.ID, strings.Join(m.BuildID, ","))
		}
	})
	return nil
}

func searchByVersion(query string) error {
	list, err := loadPackageList()
	if err != nil {
		return err
	}
	results := list.SearchByVersionPrefix(query)
	app.EmitResult(results, func() {
		if len(results) == 0 {
			fmt.Println("no matching versions; try `pwnlibc mirror update` first")
			return
		}
		for _, p := range results {
			fmt.Printf("%-28s arch=%-8s mirrors=%s\n", p.VersionArch(), p.Arch, strings.Join(p.Mirrors, ","))
		}
	})
	return nil
}

func searchLocal(libcPath string, symbols []string, endsWith, str string) error {
	info, f, err := elfinfo.Load(libcPath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	allSyms := elfinfo.Symbols(f)

	var matched []elfinfo.Symbol
	switch {
	case len(symbols) > 0:
		for _, sym := range allSyms {
			for _, pattern := range symbols {
				if elfinfo.MatchGlob(pattern, sym.Name) {
					matched = append(matched, sym)
					break
				}
			}
		}
	case endsWith != "":
		for _, sym := range allSyms {
			if strings.HasSuffix(fmt.Sprintf("%x", sym.Value), strings.ToLower(endsWith)) {
				matched = append(matched, sym)
			}
		}
	case str != "":
		offsets, err := elfinfo.StringsInDataSections(f, str)
		if err != nil {
			return err
		}
		app.EmitResult(map[string]interface{}{"path": libcPath, "string": str, "offsets_hex": hexAll(offsets)}, func() {
			if len(offsets) == 0 {
				fmt.Printf("%q not found in .rodata/.data\n", str)
				return
			}
			for _, o := range offsets {
				fmt.Printf("0x%x\n", o)
			}
		})
		return nil
	default:
		matched = allSyms
	}

	app.EmitResult(map[string]interface{}{"path": libcPath, "build_id": info.BuildID, "symbols": matched}, func() {
		for _, s := range matched {
			fmt.Printf("%-32s 0x%x\n", s.Name, s.Value)
		}
	})
	return nil
}

func hexAll(vs []uint64) []string {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = fmt.Sprintf("0x%x", v)
	}
	return out
}

func searchBySymbols(symArgs []string, tol int) error {
	query := map[string]string{}
	for _, s := range symArgs {
		parts := strings.SplitN(s, "=", 2)
		if len(parts) != 2 {
			return fmt.Errorf("--symbol must be name=addr for reverse lookup, got %q", s)
		}
		if _, err := strconv.ParseUint(strings.TrimPrefix(parts[1], "0x"), 16, 64); err != nil {
			return fmt.Errorf("invalid hex address in --symbol %q: %w", s, err)
		}
		query[parts[0]] = parts[1]
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	client := libcrip.NewClient()
	matches, err := client.Find(ctx, query)
	if err != nil {
		return err
	}
	if tol > 0 {
		matches = filterByTolerance(matches, query, tol)
	}

	app.EmitResult(matches, func() {
		if len(matches) == 0 {
			fmt.Println("no libc.rip matches")
			return
		}
		for _, m := range matches {
			fmt.Printf("%-24s buildid=%s\n", m.ID, strings.Join(m.BuildID, ","))
		}
	})
	return nil
}

func filterByTolerance(matches []libcrip.Match, query map[string]string, tol int) []libcrip.Match {
	var out []libcrip.Match
	for _, m := range matches {
		ok := true
		for name, wantHex := range query {
			want, _ := strconv.ParseUint(strings.TrimPrefix(wantHex, "0x"), 16, 64)
			gotHex, exists := m.Symbols[name]
			if !exists {
				ok = false
				break
			}
			got, err := strconv.ParseUint(strings.TrimPrefix(gotHex, "0x"), 16, 64)
			if err != nil {
				ok = false
				break
			}
			diff := int64(want) - int64(got)
			if diff < 0 {
				diff = -diff
			}
			if diff > int64(tol) {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, m)
		}
	}
	return out
}

func loadPackageList() (*packages.List, error) {
	list, err := packages.LoadList(app.Paths.PackageList())
	if err != nil {
		return nil, fmt.Errorf("no package list cached yet, run `pwnlibc mirror update` first: %w", err)
	}
	return list, nil
}
