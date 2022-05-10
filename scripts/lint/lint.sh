echo "- Running golangci-lint"

lintresult=$(golangci-lint --config .golangci.yml --out-format github-actions run)

if [[ -n $lintresult ]]; then
    echo "Some files aren't passing lint, please run 'golangci-lint run' to see the errors it flags and correct your source code before committing"
    echo $lintresult
    exit 1
  fi
  if [ $? -ne 0 ]; then
    exit 1
  fi
  echo "- Lint passed sucessfully!"

# Prevent pushing to main
protected_branch='main'
current_branch=$(git symbolic-ref HEAD | sed -e 's,.*/\(.*\),\1,')
if [ $protected_branch = $current_branch ]; then
  echo "pushing to main is not allowed"
  exit 1
fi