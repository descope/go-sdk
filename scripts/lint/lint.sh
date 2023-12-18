#!/usr/bin/env bash

GITLEAKS_VERSION="v8.8.11"
CURRENT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

run_linter() {
	while [[ "$#" -gt 0 ]]
	do
		case $1 in
			-bf|--build-folder)
					local BUILD_FOLDER="$2"
					;;
			-gc|--golangci-config)
					local GOLANGCI_CONFIG="$2"
					;;
      -dncm|--do-not-check-main)
					local DO_NOT_CHECK_MAIN="$2"
					;;
		esac
		shift
	done

	lint_check_not_main $DO_NOT_CHECK_MAIN
	lint_go_mod
	lint_go_build $BUILD_FOLDER
	lint_run_golangci $GOLANGCI_CONFIG
	lint_find_secrets
	lint_done
}

# Prevent pushing to main
lint_check_not_main() {
	echo "- Check branch protection"
	if [ -z "$1"  ]; then
		protected_branch='main'
		current_branch=$(git symbolic-ref HEAD | sed -e 's,.*/\(.*\),\1,')
		if [ $protected_branch = $current_branch ]; then
			echo "pushing to main is not allowed"
			exit 1
		fi
	fi
}

# Run go mod commands
lint_go_mod() {
	echo "- Running go tidy and go mod vendor"
	go mod tidy
	go mod vendor
}

# Run go build (default is cmd dir)
lint_go_build() {
	local folder="${1:-"cmd"}" # get first argument and set "cmd" to be default
	echo "- Running go build for: ${folder}"
	go build ${folder}
	buildcount="$(echo $?)"
	if [ $buildcount -gt 0 ]; then
		echo "Project does not compile, run go build to check what are the errors"
		exit 1
	fi
}

# Run golangci-lint
lint_run_golangci() {
	echo "- Running golangci-lint"
	GOLANG_CI_SUPPORTED_VERSION="1.51.2"
	INSTALLED_GOLANG_CLI_VERSION="$(golangci-lint --version)"
	if [[ $INSTALLED_GOLANG_CLI_VERSION != *"$GOLANG_CI_SUPPORTED_VERSION"* ]]; then
		echo "Installing golangci-lint for the first time..."
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -d -b "$(go env GOPATH)"/bin v$GOLANG_CI_SUPPORTED_VERSION
		echo "Done downloading golangci-lint"
	fi

	local golang_cli_config="${1:-"${CURRENT_DIR}/.golangci.yml"}" # get first argument and set "cmd" to be default
	lintresult=$(golangci-lint --config ${golang_cli_config} --out-format github-actions run)
	if [[ -n $lintresult ]]; then
		echo "Some files aren't passing lint, please run 'golangci-lint run' to see the errors it flags and correct your source code before committing"
		echo $lintresult
		exit 1
	fi
	if [ $? -ne 0 ]; then
		exit 1
	fi
	echo "- Lint passed sucessfully!"
}

# Run detect-secrets
lint_find_secrets() {
	echo "- Running secrets check"
	INSTALLED_SECRETS_VERSION="$(docker inspect ghcr.io/zricethezav/gitleaks:$GITLEAKS_VERSION)"
	if [[ -z $INSTALLED_SECRETS_VERSION ]]; then
		echo "Installing gitleaks for the first time..."
		git pull ghcr.io/zricethezav/gitleaks:$GITLEAKS_VERSION
		echo "Done installing gitleaks"
	fi
	echo "  - Finding leaks in git log"
	docker run --rm -v ${CURRENT_DIR}:/conf -v ${PWD}:/code ghcr.io/zricethezav/gitleaks:$GITLEAKS_VERSION detect -v --redact --source="/code" -c /conf/gitleaks.toml
	if [ $? -ne 0 ]; then
		exit 1
	fi
	echo "  - Finding leaks in local repo"
	docker run --rm -v ${CURRENT_DIR}:/conf -v ${PWD}:/code ghcr.io/zricethezav/gitleaks:$GITLEAKS_VERSION detect --no-git -v --redact --source="/code" -c /conf/gitleaks.toml
	if [ $? -ne 0 ]; then
		exit 1
	fi
	echo "- Secrets check passed sucessfully!"
}

# Indicates done
lint_done() {
	echo "Done!"
	exit 0
}
