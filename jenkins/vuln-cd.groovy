pipeline {
    agent any 
    parameters {
        string(name: 'IMAGE_TAG', defaultValue: '', description: 'This is an updated tag from CI')
    }
    environment {
        GIT_REPO    = 'https://github.com/furkhan-2000/Vuln_Prism.git'
        DOCKER_IMAGE = 'furkhan2000/shark'
        DOCKER_TAG   = "${IMAGE_TAG}"
    }
    stages {
        stage ('Cleaning') {
            steps {
                cleanWs()
            }
        }
        stage ('Verify CI Image Tag') {
            steps {
                script {
                    if (!env.DOCKER_TAG?.trim()) {
                        error "Image tag from CI not found"
                    }
                    echo "Latest Image Found: ${env.DOCKER_TAG}"
                }
            }
        }
        stage ('Authenticating & Pushing') {
            steps {
                withCredentials([usernamePassword(
                    credentialsId: 'githubCred',
                    usernameVariable: 'GITHUB_USERNAME',
                    passwordVariable: 'GITHUB_PASSWORD'
                )]) {
                    sh '''
                        set -e
                        git clone ${GIT_REPO} kubernetes_deps
                        cd kubernetes_deps
                        sed -i "s|image: ${DOCKER_IMAGE}:.*|image: ${DOCKER_IMAGE}:vuln-${DOCKER_TAG}|g" kubernetes_deps/front-end.yaml
                        sed -i "s|image: ${DOCKER_IMAGE}:.*|image: ${DOCKER_IMAGE}:sast-${DOCKER_TAG}|g" kubernetes_deps/sast.yaml
                        sed -i "s|image: ${DOCKER_IMAGE}:.*|image: ${DOCKER_IMAGE}:cyber-${DOCKER_TAG}|g" kubernetes_deps/cyber.yaml
                        git config user.name "jenkins"
                        git config user.email "jenkins8080@icloud.com"
                        git add kubernetes_deps/front-end.yaml kubernetes_deps/sast.yaml kubernetes_deps/cyber.yaml
                        git commit -m "Updating all latest images and tags [ci skip]"
                        git push https://${GITHUB_USERNAME}:${GITHUB_PASSWORD}@github.com/furkhan-2000/Vuln_Prism
                    '''
                }
            }
        }
        stage ('Check Rollout Status') {
            steps {
                script {
                    def deployments = [
                        [name: 'vuln', dep: 'vuln-dep'],
                        [name: 'cyber', dep: 'cyber-dep'],
                        [name: 'sast', dep: 'sast-dep']
                    ]
                    for (d in deployments) {
                        def status = sh(
                            script: "kubectl rollout status deployment/${d.dep} --namespace=mustang --timeout=90s",
                            returnStatus: true
                        )
                        if (status != 0) {
                            echo "${d.name} deployment rollout failed. Attempting rollback..."
                            sh "kubectl rollout undo deployment/${d.dep} --namespace=mustang"
                            def rollbackStatus = sh(
                                script: "kubectl rollout status deployment/${d.dep} --namespace=mustang --timeout=90s",
                                returnStatus: true
                            )
                            if (rollbackStatus != 0) {
                                error "${d.name} main deployment rollback failed; manual intervention required."
                            } else {
                                echo "${d.name} deployment failed, but rollback succeeded."
                            }
                        } else {
                            echo "${d.name} deployment is healthy."
                        }
                    }
                }
            }
        }
    }
    post {
        success {
            echo "Build success"
            mail(
                to: 'furkhan2000@icloud.com',
                subject: "Pipeline success: vulnPrism-CI #${env.BUILD_NUMBER}",
                body: "The vulnPrism-CI pipeline has succeeded. ${env.BUILD_URL}"
            )
        }
        failure {
            echo "❌ Build failed. Sending email notification"
            mail(
                to: 'furkhan2000@icloud.com',
                subject: "Pipeline Failed: vulnPrism-CD #${env.BUILD_NUMBER}",
                body: "The vulnPrism-CD pipeline has failed. Please investigate the failure at: ${env.BUILD_URL}"
            )
        }
    }
}