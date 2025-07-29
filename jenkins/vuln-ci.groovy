pipeline {
    agent any
    environment {
        SONAR_HOME = tool 'sonar'
    }
    stages {
        stage('Cleaning') {
            steps {
                cleanWs()
                echo "🧹 Workspace cleaned"
            }
        }
        stage('Cloning Repo') {
            steps {
                git url: 'https://github.com/furkhan-2000/Vuln_Prism.git', branch: 'main'
                echo "📦 Repo cloned successfully"
            }
        }
        stage('Dynamic Tagging') {
            steps {
                script {
                    def commitHash = sh(script: "git rev-parse --short HEAD", returnStdout: true).trim()
                    env.IMAGE_TAG = commitHash
                    echo "🏷️ Image tag set to ${env.IMAGE_TAG}"
                }
            }
        }
        stage('SAST - SonarQube') {
            steps {
                withSonarQubeEnv('sonar') {
                    sh "${SONAR_HOME}/bin/sonar-scanner -Dsonar.projectName=VulnPrism -Dsonar.projectKey=VulnPrism"
                }
                echo "🔍 SonarQube analysis complete"
            }
        }
        stage('Sonar Quality Gate') {
            steps {
                timeout(time: 2, unit: 'MINUTES') {
                    script {
                        def qg = waitForQualityGate(abortPipeline: false)
                        if (qg.status != "OK") {
                            error "❌ Quality Gate Failed: ${qg.status}"
                        }
                    }
                }
                echo "✅ Quality Gate passed"
            }
        }
        stage('OWASP Dependency-Check') {
            steps {
                timeout(time: 27, unit: 'MINUTES') {
                    retry(2) {
                        dependencyCheck additionalArguments: '--scan . --format XML --out ./ --prettyPrint', odcInstallation: 'owasp'
                    }
                    dependencyCheckPublisher pattern: 'dependency-check-report.xml'
                    echo "🛡️ OWASP dependency check completed"
                }
            }
        }
        stage('Trivy Vulnerability Scan') {
            steps {
                sh "trivy fs ./ --cache-dir ./trivyresult"
                echo "🔍 Trivy scan completed"
            }
        }
        stage('Prune & Rebuild Docker Compose') {
            steps {
                sh '''
                    docker compose down
                    docker image prune -a -f
                    docker system prune --all -f
                    docker compose up -d
                '''
                echo "🛠️ Docker images pruned and containers rebuilt"
            }
        }
        stage('Push Docker Images') {
            steps {
                withCredentials([usernamePassword(
                    credentialsId: 'dockerHubCred',
                    usernameVariable: 'DOCKERHUB_USERNAME',
                    passwordVariable: 'DOCKERHUB_PASSWORD'
                )]) {
                    sh '''
                        docker tag vuln-ci-cyberscythe:latest $DOCKERHUB_USERNAME/shark:${IMAGE_TAG}-cyber
                        docker tag vuln-ci-sast:latest $DOCKERHUB_USERNAME/shark:${IMAGE_TAG}-sast
                        docker tag vuln-ci-chatbot-frontend:latest $DOCKERHUB_USERNAME/shark:${IMAGE_TAG}-vulnmain

                        echo "🔐 Logging into DockerHub"
                        docker login -u $DOCKERHUB_USERNAME -p $DOCKERHUB_PASSWORD

                        echo "📤 Pushing images..."
                        docker push $DOCKERHUB_USERNAME/shark:${IMAGE_TAG}-cyber
                        docker push $DOCKERHUB_USERNAME/shark:${IMAGE_TAG}-sast
                        docker push $DOCKERHUB_USERNAME/shark:${IMAGE_TAG}-vulnmain
                    '''
                }
            }
        }
    }
    post {
        success {
            echo "🚀 CI pipeline succeeded. Triggering CD..."
            build job: 'vulnPrism-CD',
                  parameters: [string(name: 'IMAGE_TAG', value: "${env.IMAGE_TAG}")],
                  wait: false,
                  propagate: false
        }
        failure {
            echo "❌ Build failed. Sending email notification"
            mail(
                to: 'furkhan2000@icloud.com',
                subject: "Pipeline Failed: vulnPrism-CI #${env.BUILD_NUMBER}",
                body: "The vulnPrism-CI pipeline has failed. Please investigate the failure at: ${env.BUILD_URL}"
            )
        }
    }
}

