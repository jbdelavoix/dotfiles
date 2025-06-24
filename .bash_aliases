# unix alias
alias ll="ls -alF"

# terraform
alias tf-fmt="find . -type f -name '*.tf*' |sed -r 's|/[^/]+$||' |grep -v '/.terraform' |grep -v '/.history/' |sort |uniq |xargs -I % sh -c 'terraform fmt %'"
alias tf-lint="find . -type f -name '*.tf*' |sed -r 's|/[^/]+$||' |grep -v '/.terraform' |grep -v '/.history/' |sort |uniq |xargs -I % sh -c 'tflint -c ~/.tflint.hcl %'"
alias tf-docs="find . -type f -name '*.tf*' |sed -r 's|/[^/]+$||' |grep -v '/.terraform' |grep -v '/.history/' |sort |uniq |xargs -I % sh -c 'cd % && terraform-docs markdown . > doc.md && cd -'"
alias tf-docs-readme="find . -type f -name '*.tf*' |sed -r 's|/[^/]+$||' |grep -v '/.terraform' |grep -v '/.history/' |sort |uniq |xargs -I % sh -c 'cd % && terraform-docs markdown . > README.md && cd -'"
alias tf-clean="find . -type d -name .terraform -exec rm -rf {} + && find . -type f -name .terraform.lock.hcl -exec rm -rf {} + && find . -type d -name artifacts -exec rm -rf {} + "

# git
alias git-hub-user="git config user.name 'jbdelavoix'; git config user.email 'jbdelavoix@users.noreply.github.com'"
alias git-clean="find . -type d -empty -delete && git ls-files --exclude-standard -ozi | xargs -0 rm -rf"

# python
function py-fmt() {
    autoflake --in-place --remove-unused-variables $1
    black $1
    isort $1
}

export PATH="$PATH:$(pwd)/binaries"
