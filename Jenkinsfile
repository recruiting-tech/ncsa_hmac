#!groovy

// The git committer for the current sha pointer.
def String committerInfo = ""
// Load common Jenkinsfile functions from the jenkins host
def test = node { load "/var/lib/jenkins/groovy-pipeline/test.groovy" }
def docker = node { load "/var/lib/jenkins/groovy-pipeline/docker.groovy" }

node {
  label("Build")
  stage('Build image artifact') {
    checkout scm
    sh 'git --no-pager show -s --format="%an -- %ae" | head -1 > committerInfo.txt'
    committerInfo = readFile('committerInfo.txt').trim()
    echo "committerInfo: ${committerInfo}"
  }

  stage('Test image') {
    // invokes ./script/test.sh
    def Boolean testFailure = false
    testFailure = test.run(committerInfo, env.JOB_NAME, env.BUILD_URL)
    if (testFailure) {
      error() // Throw an exception and abort execution
    }
  }
}

node {
  stage('Cleanup') {
    docker.cleanup()
  }
}
