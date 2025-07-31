pipeline {
    agent any 
    parameters {
        string(name: 'IMAGE_TAG', defaultValue: '', description: 'This is an updated tag from CI')
    }
    environment {
        GIT_REPO    = 'https://github.com/furkhan-2000/Vuln_Prism.git'
        DOCKER_IMAGE = 'furkhan2000/shark'
        DOCKER_TAG   = "${IMAGE_TAG}"
        HELM_DIR     = 'Vuln_Prism/helm'
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
        stage ('Update Helm values.yaml and Push') {
            steps {
                withCredentials([usernamePassword(
                    credentialsId: 'githubCred',
                    usernameVariable: 'GITHUB_USERNAME',
                    passwordVariable: 'GITHUB_PASSWORD'
                )]) {
                    sh '''
                        set -e
                        git clone ${GIT_REPO}
                        cd ${HELM_DIR}
                        # Update image tags in values.yaml using yq
                        yq e '.vuln.rollout.spec.template.spec.containers[0].image = "${DOCKER_IMAGE}:front-end-${DOCKER_TAG}"' -i values.yaml
                        yq e '.sast.rollout.spec.template.spec.containers[0].image = "${DOCKER_IMAGE}:sast-${DOCKER_TAG}"' -i values.yaml
                        yq e '.cyber.rollout.spec.template.spec.containers[0].image = "${DOCKER_IMAGE}:cyber-${DOCKER_TAG}"' -i values.yaml
                        git config user.name "jenkins"
                        git config user.email "jenkins8080@icloud.com"
                        git add values.yaml
                        git commit -m "Update image tags to ${DOCKER_TAG} [ci skip]"
                        git push https://${GITHUB_USERNAME}:${GITHUB_PASSWORD}@github.com/furkhan-2000/Vuln_Prism.git
                    '''
                }
            }
        }
        stage ('Wait for ArgoCD Sync') {
            steps {
                script {
                    echo "Waiting 60 seconds for ArgoCD to sync..."
                    sleep(time: 60, unit: 'SECONDS')
                }
            }
        }
        stage ('Check Rollout Status') {
            steps {
                withCredentials([usernamePassword(
                    credentialsId: 'githubCred',
                    usernameVariable: 'GITHUB_USERNAME',
                    passwordVariable: 'GITHUB_PASSWORD'
                )]) {
                    script {
                        def rollouts = [
                            [name: 'vuln', rollout: 'vuln-rollout'],
                            [name: 'cyber', rollout: 'cyber-rollout'],
                            [name: 'sast', rollout: 'sast-rollout']
                        ]
                        for (r in rollouts) {
                            // Use shell timeout to limit the wait time
                            def status = sh(
                                script: "timeout 90s kubectl argo rollouts get rollout ${r.rollout} --namespace=mustang --watch",
                                returnStatus: true
                            )
                            if (status != 0) {
                                echo "${r.name} rollout failed. Rolling back via Git revert..."
                                sh '''
                                    cd Vuln_Prism/helm
                                    git revert HEAD
                                    git push https://${GITHUB_USERNAME}:${GITHUB_PASSWORD}@github.com/furkhan-2000/Vuln_Prism.git
                                '''
                                error "${r.name} rollout failed and rollback triggered. Manual intervention may be required."
                            } else {
                                echo "${r.name} rollout is healthy."
                            }
                        }

                    }
                }
            }
        }
        stage ('packging into helm') {
            steps {
                script {
                    try {
                        sh '''
                        cd ${HELM_DIR} 
                        echo "Linting Helm Chart"
                        helm lint --strict .
                        '''
                    } catch (error) { 
                        error "🪳 Helm lint failed! please fix the chart issue before packging"
                    }
                    sh '''
                        cd ${HELM_DIR}
                        echo "packging helm chart" 
                        helm package . 
                        echo "Helm chart packaged successfully"
                    '''
                }
            }
        }
        stage ('Releasing') {
            steps {
                withCredentials([string(credentialsId: '', variable: 'GITHUB_TOKEN')]) {
                    sh '''
                        export GH_TOKEN=$GITHUB_TOKEN 
                        gh release create ...
                    '''
                }
            }
        }
    }
    post {
        success {
            echo "Build success"
            mail(
                to: 'furkhan2000@icloud.com',
                subject: "Pipeline success: vulnPrism-CD #${env.BUILD_NUMBER}",
                body: "The vulnPrism-CD pipeline has succeeded. ${env.BUILD_URL}"
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